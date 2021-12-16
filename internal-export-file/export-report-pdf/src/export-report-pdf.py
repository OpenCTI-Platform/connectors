import yaml
import os
import time
import datetime
from pycti.utils.constants import StixCyberObservableTypes
from weasyprint import HTML
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
)
from jinja2 import Environment, FileSystemLoader


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
        self.set_colors()
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

    def _process_message(self, data):
        file_name = data["file_name"]
        # TODO this can be implemented to filter every entity and observable
        # max_marking = data["max_marking"]
        entity_type = data["entity_type"]

        if entity_type != "Report":
            raise ValueError(
                f'This Connector can only process entities of type "Report" and not of type "{entity_type}".'
            )

        # Get the Report
        report_dict = self.helper.api.report.read(id=data["entity_id"])

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
                observable_dict = self.helper.api.stix_cyber_observable.read(id=obj_id)

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
                reader_func = self.get_reader(obj_entity_type)
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
        env = Environment(loader=FileSystemLoader(os.path.abspath(os.getcwd())))
        template = env.get_template("src/resources/report.html")
        html_string = template.render(context)

        # Generate pdf from html string
        pdf_contents = HTML(string=html_string, base_url="src/resources").write_pdf()

        # Upload the output pdf
        self.helper.log_info(f"Uploading: {file_name}")
        self.helper.api.stix_domain_object.add_file(
            id=report_id,
            file_name=file_name,
            data=pdf_contents,
            mime_type="application/pdf",
        )
        return "Export done"

    def set_colors(self):
        with open("src/resources/report.css.template", "r") as f:
            new_css = f.read()
            new_css = new_css.replace("<primary_color>", self.primary_color)
            new_css = new_css.replace("<secondary_color>", self.secondary_color)

        with open("src/resources/report.css", "w") as f:
            f.write(new_css)

    def get_reader(self, entity_type):
        """
        Returns the function to use for calling the OpenCTI to
        read data for a particular entity type.

        entity_type: a str representing the entity type, i.e. Indicator

        returns: a function or None if entity type is not supported
        """
        reader = {
            "Stix-Domain-Object": self.helper.api.stix_domain_object.read,
            "Attack-Pattern": self.helper.api.attack_pattern.read,
            "Campaign": self.helper.api.campaign.read,
            "Note": self.helper.api.note.read,
            "Observed-Data": self.helper.api.observed_data.read,
            "Organization": self.helper.api.identity.read,
            "Opinion": self.helper.api.opinion.read,
            "Report": self.helper.api.report.read,
            "Sector": self.helper.api.identity.read,
            "System": self.helper.api.identity.read,
            "Course-Of-Action": self.helper.api.course_of_action.read,
            "Identity": self.helper.api.identity.read,
            "Indicator": self.helper.api.indicator.read,
            "Individual": self.helper.api.identity.read,
            "Infrastructure": self.helper.api.infrastructure.read,
            "Intrusion-Set": self.helper.api.intrusion_set.read,
            "Malware": self.helper.api.malware.read,
            "Threat-Actor": self.helper.api.threat_actor.read,
            "Tool": self.helper.api.tool.read,
            "Vulnerability": self.helper.api.vulnerability.read,
            "Incident": self.helper.api.incident.read,
            "City": self.helper.api.location.read,
            "Country": self.helper.api.location.read,
            "Region": self.helper.api.location.read,
            "Position": self.helper.api.location.read,
            "Location": self.helper.api.location.read,
        }
        return reader.get(entity_type, None)

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
        exit(0)
