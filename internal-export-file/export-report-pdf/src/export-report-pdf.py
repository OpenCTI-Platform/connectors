import base64
import datetime
import io
import os
import sys
import time
import cairosvg
import yaml
from jinja2 import Environment, FileSystemLoader
from pycti import OpenCTIConnectorHelper, get_config_variable
from pycti.utils.constants import StixCyberObservableTypes
from pygal_maps_world.i18n import COUNTRIES
from pygal_maps_world.maps import World
from weasyprint import HTML


class ExportReportPdf:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # ExportReportPdf specific config settings
        self.primary_color = get_config_variable(
            "EXPORT_REPORT_PDF_PRIMARY_COLOR",
            ["export_report_pdf", "primary_color"],
            config,
        )
        self.secondary_color = get_config_variable(
            "EXPORT_REPORT_PDF_SECONDARY_COLOR",
            ["export_report_pdf", "secondary_color"],
            config,
        )
        self.current_dir = os.path.abspath(os.path.dirname(__file__))
        self._set_colors()
        self.company_address_line_1 = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_1",
            ["export_report_pdf", "company_address_line_1"],
            config,
        )
        self.company_address_line_2 = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_2",
            ["export_report_pdf", "company_address_line_2"],
            config,
        )
        self.company_address_line_3 = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_ADDRESS_LINE_3",
            ["export_report_pdf", "company_address_line_3"],
            config,
        )
        self.company_phone_number = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_PHONE_NUMBER",
            ["export_report_pdf", "company_phone_number"],
            config,
        )
        self.company_email = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_EMAIL",
            ["export_report_pdf", "company_email"],
            config,
        )
        self.company_website = get_config_variable(
            "EXPORT_REPORT_PDF_COMPANY_WEBSITE",
            ["export_report_pdf", "company_website"],
            config,
        )
        self.indicators_only = get_config_variable(
            "EXPORT_REPORT_PDF_INDICATORS_ONLY",
            ["export_report_pdf", "indicators_only"],
            config,
        )
        self.defang_urls = get_config_variable(
            "EXPORT_REPORT_PDF_DEFANG_URLS",
            ["export_report_pdf", "defang_urls"],
            config,
        )

    def _get_readable_date_time(self, str_date_time):
        """
        Convert ISO date times to readable format

        str_date_time: a str representing date/time in ISO format
        """

        dt = datetime.datetime.fromisoformat(str_date_time)
        return dt.strftime("%B %d, %I:%M%p")

    def _process_message(self, data):
        file_name = data["file_name"]
        if "entity_type" not in data or "entity_id" not in data:
            raise ValueError(
                'This Connector currently only handles direct export (single entity and no list) of the following entity types: "Report", "Intrusion-Set", and "Threat-Actor"'
            )
        entity_type = data["entity_type"]
        entity_id = data["entity_id"]

        if entity_type == "Report":
            self._process_report(entity_id, file_name)
        elif entity_type == "Intrusion-Set":
            self._process_intrusion_set(entity_id, file_name)
        elif entity_type == "Threat-Actor":
            self._process_threat_actor(entity_id, file_name)
        else:
            raise ValueError(
                f'This connector currently only handles the entity types: "Report", "Intrusion-Set", "Threat-Actor", not "{entity_type}".'
            )

        return "Export done"

    def _process_report(self, entity_id, file_name):
        """
        Process a Report entity and upload as pdf.
        """
        # Get the Report
        report_dict = self.helper.api_impersonate.report.read(id=entity_id)

        # Extract values for inclusion in output pdf
        report_marking = report_dict.get("objectMarking", None)
        if report_marking:
            report_marking = report_marking[-1]["definition"]
        report_name = report_dict["name"]
        report_description = report_dict.get("description", "No description available.")
        report_confidence = report_dict["confidence"]
        report_id = report_dict["id"]
        report_external_refs = [
            external_ref_dict["url"]
            for external_ref_dict in report_dict["externalReferences"]
        ]
        report_objs = report_dict["objects"]
        report_date = datetime.datetime.now().strftime("%b %d %Y")

        context = {
            "report_name": report_name,
            "report_description": report_description,
            "report_marking": report_marking,
            "report_confidence": report_confidence,
            "report_external_refs": report_external_refs,
            "report_date": report_date,
            "company_address_line_1": self.company_address_line_1,
            "company_address_line_2": self.company_address_line_2,
            "company_address_line_3": self.company_address_line_3,
            "company_phone_number": self.company_phone_number,
            "company_email": self.company_email,
            "company_website": self.company_website,
            "entities": {},
            "observables": {},
        }

        # Process each STIX Object
        for report_obj in report_objs:
            obj_entity_type = report_obj["entity_type"]
            obj_id = report_obj["standard_id"]

            # Handle StixCyberObservables entities
            if obj_entity_type == "StixFile" or StixCyberObservableTypes.has_value(
                obj_entity_type
            ):
                observable_dict = (
                    self.helper.api_impersonate.stix_cyber_observable.read(id=obj_id)
                )

                # If only include indicators and
                # the observable doesn't have an indicator, skip it
                if self.indicators_only and not observable_dict["indicators"]:
                    self.helper.log_info(
                        f"Skipping {obj_entity_type} observable with value {observable_dict['observable_value']} as it was not an Indicator."
                    )
                    continue

                if obj_entity_type not in context["observables"]:
                    context["observables"][obj_entity_type] = []

                # Defang urls
                if self.defang_urls and obj_entity_type == "Url":
                    observable_dict["observable_value"] = observable_dict[
                        "observable_value"
                    ].replace("http", "hxxp", 1)

                context["observables"][obj_entity_type].append(observable_dict)

            # Handle all other entities
            else:
                reader_func = self._get_reader(obj_entity_type)
                if reader_func is None:
                    self.helper.log_error(
                        f'Could not find a function to read entity with type "{obj_entity_type}"'
                    )
                    continue
                entity_dict = reader_func(id=obj_id)

                if obj_entity_type not in context["entities"]:
                    context["entities"][obj_entity_type] = []

                context["entities"][obj_entity_type].append(entity_dict)

        # Render html with input variables
        env = Environment(
            loader=FileSystemLoader(self.current_dir), finalize=self._finalize
        )
        template = env.get_template("resources/report.html")
        html_string = template.render(context)

        # Generate pdf from html string
        pdf_contents = HTML(
            string=html_string, base_url=f"{self.current_dir}/resources"
        ).write_pdf()

        # Upload the output pdf
        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            report_id, file_name, pdf_contents, "application/pdf"
        )

    def _process_intrusion_set(self, entity_id, file_name):
        """
        Process an Intrusion Set entity and upload as pdf.
        """

        now_date = datetime.datetime.now().strftime("%b %d %Y")

        # Store context for usage in html template
        context = {
            "entities": {},
            "target_map_country": None,
            "report_date": now_date,
            "company_address_line_1": self.company_address_line_1,
            "company_address_line_2": self.company_address_line_2,
            "company_address_line_3": self.company_address_line_3,
            "company_phone_number": self.company_phone_number,
            "company_email": self.company_email,
            "company_website": self.company_website,
        }

        # Get a bundle of all objects affiliated with the intrusion set
        intrusion_set_objs = self.helper.api_impersonate.stix2.export_entity(
            "Intrusion-Set", entity_id, "full"
        )

        for intrusion_set_obj in intrusion_set_objs["objects"]:
            obj_id = intrusion_set_obj["id"]
            obj_entity_type = intrusion_set_obj["type"]

            reader_func = self._get_reader(obj_entity_type)
            if reader_func is None:
                self.helper.log_error(
                    f'Could not find a function to read entity with type "{obj_entity_type}"'
                )
                continue

            time.sleep(0.3)
            entity_dict = reader_func(id=obj_id)

            # Key names cannot have - in them for jinja2 templating
            obj_entity_type = obj_entity_type.replace("-", "_")
            if obj_entity_type not in context["entities"]:
                context["entities"][obj_entity_type] = []

            context["entities"][obj_entity_type].append(entity_dict)

        # Generate the svg img contents for the targets map
        if "relationship" in context["entities"]:

            # Create world map
            world_map = World()
            world_map.title = "Targeted Countries"
            targeted_countries = []
            for relationship in context["entities"]["relationship"]:
                if (
                    relationship["entity_type"] == "targets"
                    and relationship["relationship_type"] == "targets"
                    and relationship["to"]["entity_type"] == "Country"
                ):
                    country_code = relationship["to"]["name"].lower()
                    if not self._validate_country_code(country_code):
                        self.helper.log_warning(
                            f"{country_code} is not a supported country code, skipping..."
                        )
                        continue

                    targeted_countries.append(country_code)

            # Build targeted countries image
            if targeted_countries:
                world_map.add("Targeted Countries", targeted_countries)
                # Convert the svg to base64 png
                svg_bytes = world_map.render()
                png_bytes = io.BytesIO()
                cairosvg.svg2png(bytestring=svg_bytes, write_to=png_bytes)
                base64_png = base64.b64encode(png_bytes.getvalue()).decode()
                context["target_map_country"] = f"data:image/png;base64, {base64_png}"

        # Render html with input variables
        env = Environment(
            loader=FileSystemLoader(self.current_dir), finalize=self._finalize
        )
        template = env.get_template("resources/intrusion-set.html")
        html_string = template.render(context)

        # Generate pdf from html string
        pdf_contents = HTML(
            string=html_string, base_url=f"{self.current_dir}/resources"
        ).write_pdf()

        # Upload the output pdf
        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id, file_name, pdf_contents, "application/pdf"
        )

    def _process_threat_actor(self, entity_id, file_name):
        """
        Process a Threat Actor entity and upload as pdf.
        """

        now_date = datetime.datetime.now().strftime("%b %d %Y")

        # Store context for usage in html template
        context = {
            "entities": {},
            "target_map_country": None,
            "report_date": now_date,
            "company_address_line_1": self.company_address_line_1,
            "company_address_line_2": self.company_address_line_2,
            "company_address_line_3": self.company_address_line_3,
            "company_phone_number": self.company_phone_number,
            "company_email": self.company_email,
            "company_website": self.company_website,
        }

        # Get a bundle of all objects affiliated with the threat actor
        bundle = self.helper.api_impersonate.stix2.export_entity(
            "Threat-Actor", entity_id, "full"
        )

        for bundle_obj in bundle["objects"]:
            obj_id = bundle_obj["id"]
            obj_entity_type = bundle_obj["type"]

            reader_func = self._get_reader(obj_entity_type)
            if reader_func is None:
                self.helper.log_error(
                    f'Could not find a function to read entity with type "{obj_entity_type}"'
                )
                continue

            time.sleep(0.3)
            entity_dict = reader_func(id=obj_id)

            # Key names cannot have - in them for jinja2 templating
            obj_entity_type = obj_entity_type.replace("-", "_")
            if obj_entity_type not in context["entities"]:
                context["entities"][obj_entity_type] = []

            context["entities"][obj_entity_type].append(entity_dict)

        # Generate the svg img contents for the targets map
        if "relationship" in context["entities"]:

            # Create world map
            world_map = World()
            world_map.title = "Targeted Countries"
            targeted_countries = []
            for relationship in context["entities"]["relationship"]:
                if (
                    relationship["entity_type"] == "targets"
                    and relationship["relationship_type"] == "targets"
                    and relationship["to"]["entity_type"] == "Country"
                ):
                    country_code = relationship["to"]["name"].lower()
                    if not self._validate_country_code(country_code):
                        self.helper.log_warning(
                            f"{country_code} is not a supported country code, skipping..."
                        )
                        continue

                    targeted_countries.append(country_code)

            # Build targeted countries image
            if targeted_countries:
                world_map.add("Targeted Countries", targeted_countries)
                # Convert the svg to base64 png
                svg_bytes = world_map.render()
                png_bytes = io.BytesIO()
                cairosvg.svg2png(bytestring=svg_bytes, write_to=png_bytes)
                base64_png = base64.b64encode(png_bytes.getvalue()).decode()
                context["target_map_country"] = f"data:image/png;base64, {base64_png}"

        # Render html with input variables
        env = Environment(
            loader=FileSystemLoader(self.current_dir), finalize=self._finalize
        )
        template = env.get_template("resources/threat-actor.html")
        html_string = template.render(context)

        # Generate pdf from html string
        pdf_contents = HTML(
            string=html_string, base_url=f"{self.current_dir}/resources"
        ).write_pdf()

        # Upload the output pdf
        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.push_entity_export(
            entity_id, file_name, pdf_contents, "application/pdf"
        )

    def _set_colors(self):
        for root, dirs, files in os.walk(self.current_dir):
            for file_name in files:
                if file_name.endswith(".css.template"):
                    with open(os.path.join(root, file_name), "r") as f:
                        new_css = f.read()
                        new_css = new_css.replace("<primary_color>", self.primary_color)
                        new_css = new_css.replace(
                            "<secondary_color>", self.secondary_color
                        )

                    file_name = file_name.replace(".template", "")
                    with open(os.path.join(root, file_name), "w") as f:
                        f.write(new_css)

    def _validate_country_code(self, country_code):
        """
        Returns a boolean indicating whether or not the country code is valid.
        """
        if country_code in COUNTRIES:
            return True
        return False

    def _finalize(self, data):
        """
        Used for rendering jinja2 template to supress None
        """
        return data if data is not None else "N/A"

    def _get_reader(self, entity_type):
        """
        Returns the function to use for reading the data of a particular entity type.

        entity_type: a str representing the entity type, i.e. Indicator

        returns: a function or None if entity type is not supported
        """
        reader = {
            "stix-domain-object": self.helper.api_impersonate.stix_domain_object.read,
            "attack-pattern": self.helper.api_impersonate.attack_pattern.read,
            "campaign": self.helper.api_impersonate.campaign.read,
            "event": self.helper.api_impersonate.event.read,
            "note": self.helper.api_impersonate.note.read,
            "observed-data": self.helper.api_impersonate.observed_data.read,
            "organization": self.helper.api_impersonate.identity.read,
            "opinion": self.helper.api_impersonate.opinion.read,
            "report": self.helper.api_impersonate.report.read,
            "sector": self.helper.api_impersonate.identity.read,
            "system": self.helper.api_impersonate.identity.read,
            "course-of-action": self.helper.api_impersonate.course_of_action.read,
            "identity": self.helper.api_impersonate.identity.read,
            "indicator": self.helper.api_impersonate.indicator.read,
            "individual": self.helper.api_impersonate.identity.read,
            "infrastructure": self.helper.api_impersonate.infrastructure.read,
            "intrusion-set": self.helper.api_impersonate.intrusion_set.read,
            "malware": self.helper.api_impersonate.malware.read,
            "threat-actor": self.helper.api_impersonate.threat_actor.read,
            "tool": self.helper.api_impersonate.tool.read,
            "channel": self.helper.api_impersonate.channel.read,
            "narrative": self.helper.api_impersonate.narrative.read,
            "language": self.helper.api_impersonate.language.read,
            "vulnerability": self.helper.api_impersonate.vulnerability.read,
            "incident": self.helper.api_impersonate.incident.read,
            "city": self.helper.api_impersonate.location.read,
            "country": self.helper.api_impersonate.location.read,
            "region": self.helper.api_impersonate.location.read,
            "position": self.helper.api_impersonate.location.read,
            "location": self.helper.api_impersonate.location.read,
            "relationship": self.helper.api_impersonate.stix_core_relationship.read,
        }
        return reader.get(entity_type.lower(), None)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector_export_report_pdf = ExportReportPdf()
        connector_export_report_pdf.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
