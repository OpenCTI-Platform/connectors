import json
import os
import traceback
from datetime import datetime
from typing import Dict

import stix2
import yaml
from greynoise import GreyNoise
from pycti import (
    Identity,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
    get_config_variable,
)


class GreyNoiseVulnConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)
        self.greynoise_key = get_config_variable(
            "GREYNOISE_KEY", ["greynoise-vuln", "key"], config
        )
        self.max_tlp = get_config_variable(
            "GREYNOISE_MAX_TLP", ["greynoise-vuln", "max_tlp"], config
        )
        self.greynoise_ent_name = get_config_variable(
            "GREYNOISE_NAME", ["greynoise-vuln", "name"], config
        )
        self.greynoise_ent_desc = get_config_variable(
            "GREYNOISE_DESCRIPTION", ["greynoise-vuln", "description"], config
        )

        # Define variables
        self.tlp = None
        self.stix_objects = []
        self.integration_name = "opencti-vuln-enricher-v1.0"

        self.check_api_key(force_recheck=True)

    def check_api_key(self, force_recheck=False):
        # Validate GreyNoise API Key
        self.helper.log_debug("Validating GreyNoise API Key...")
        try:
            today = datetime.today().strftime("%Y-%m-%d")

            if os.path.exists("KEY_INFO"):
                with open("KEY_INFO") as text_file:
                    key_info = text_file.read()
                key_state = json.loads(key_info)
            else:
                empty_key_state = {"offering": "", "expiration": "", "last_checked": ""}
                with open("KEY_INFO", "w") as text_file:
                    empty_key_state = json.dumps(empty_key_state)
                    print(f"{empty_key_state}", file=text_file)
                key_state = json.loads(empty_key_state)

            if key_state.get("last_checked") != today or force_recheck:
                session = GreyNoise(
                    api_key=self.greynoise_key, integration_name=self.integration_name
                )
                key_check = session.test_connection()

                key_state = {
                    "offering": key_check.get("offering"),
                    "expiration": key_check.get("expiration"),
                    "last_checked": today,
                }

                if "offering" in key_check:
                    self.helper.log_info(
                        "GreyNoise API Key Status: "
                        + str(key_check.get("offering", ""))
                        + "/"
                        + str(key_check.get("expiration", ""))
                    )
                    if key_check.get("offering") == "community_trial":
                        key_state["valid"] = True
                        self.helper.log_info("GreyNoise API key is valid!")
                    elif key_check.get("offering") == "community":
                        key_state["valid"] = False
                        self.helper.log_info(
                            "GreyNoise API key NOT valid! Update to use connector!"
                        )
                    elif (
                        key_check.get("offering") != "community"
                        and key_check.get("expiration") > today
                    ):
                        key_state["valid"] = True
                        self.helper.log_info("GreyNoise API key is valid!")
                    elif (
                        key_check.get("offering") != "community"
                        and key_check.get("expiration") < today
                    ):
                        key_state["valid"] = False

                with open("KEY_INFO", "w") as text_file:
                    key_state = json.dumps(key_state)
                    print(f"{key_state}", file=text_file)
                key_state = json.loads(key_state)

            return key_state.get("valid", False)

        except Exception as e:
            self.helper.log_error(
                "[API] GreyNoise API key is not valid or not supported for this integration. API "
                "Response: " + str(e)
            )
            raise Exception(
                "[API] GreyNoise API key is not valid or not supported for this integration. API Response: "
                + str(e)
            )

    def _extract_and_check_markings(self, opencti_entity: dict) -> bool:
        """
        Extract TLP, and we check if the variable "max_tlp" is less than
        or equal to the markings access of the entity from OpenCTI.
        If this is true, we can send the data to connector for enrichment.

        :param opencti_entity: Parameter that contains all information about the entity,
                               including "objectMarking", the marking that the observable uses.
        :return: A boolean
        """

        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                self.tlp = marking_definition["definition"]

        is_valid_max_tlp = OpenCTIConnectorHelper.check_max_tlp(self.tlp, self.max_tlp)

        return is_valid_max_tlp

    def _generate_stix_relationship(
        self,
        source_ref: str,
        stix_core_relationship_type: str,
        target_ref: str,
        start_time: str | None = None,
        stop_time: str | None = None,
    ) -> dict:
        """
        This method allows you to create a relationship in Stix2 format.

        :param source_ref: This parameter is the "from" of the relationship.
        :param stix_core_relationship_type: Parameter,
        :param target_ref: This parameter is the "to" of the relationship.
        :param start_time: This parameter is the start of the relationship. Value not required, None by default.
        :param stop_time: This parameter is the stop of the relationship. Value not required, None by default.
        :return: A dict
        """

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            start_time=start_time,
            stop_time=stop_time,
            target_ref=target_ref,
            created_by_ref=self.greynoise_identity["id"],
        )

    def _create_custom_label(self, name_label: str, color_label: str):
        """
        This method allows you to create a custom label, using the OpenCTI API.

        :param name_label: A parameter giving the name of the label.
        :param color_label: A parameter giving the color of the label.
        """

        new_custom_label = self.helper.api.label.read_or_create_unchecked(
            value=name_label, color=color_label
        )
        if new_custom_label is None:
            self.helper.connector_logger.error(
                "[ERROR] The label could not be created. If your connector does not have the permission to create "
                "labels, please create it manually before launching",
                {"name_label": name_label},
            )
        else:
            self.all_labels.append(new_custom_label["value"])

    @staticmethod
    def _get_match(data, key, value):
        return next((x for x in data if x[key] == value), None)

    def _process_labels(self, data: dict) -> tuple:
        """
        This method allows you to start the process of creating labels and recovering associated malware.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param data_tags: A parameter that contains all the data relating to the existing tags in GreyNoise
        :return: A tuple (all labels, all malwares)
        """

        self.all_labels = []

        if (
            "exploitation_activity" in data
            and "activity_seen" in data["exploitation_activity"]
            and data["exploitation_activity"]["activity_seen"]
        ):
            # Create label GreyNoise for activity_seen:true
            self._create_custom_label("gn-activity-seen", "#a6a09f")

        if (
            "exploitation_stats" in data
            and "number_of_available_exploits" in data["exploitation_stats"]
            and data["exploitation_stats"]["number_of_available_exploits"]
        ) >= 1:
            # Create label GreyNoise "malicious"
            self._create_custom_label("gn-exploits-available", "#ff8178")

        if (
            "exploitation_stats" in data
            and "number_of_threat_actors_exploiting_vulnerability"
            in data["exploitation_stats"]
            and data["exploitation_stats"][
                "number_of_threat_actors_exploiting_vulnerability"
            ]
        ) >= 1:
            # Create label GreyNoise "malicious"
            self._create_custom_label("gn-threat-actors-exploiting", "#ff8178")

        return self.all_labels

    def _generate_stix_external_reference(self, data: dict) -> list:
        """
        This method allows you to create an external reference in Stix2 format.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param sighting_not_seen: This parameter is a boolean that corresponds to the configuration of
                                  sighting_not_seen, which aims to know if the user wants to create a sighting at 0.
        :return: list -> ExternalReference (Stix2 format)
        """

        description = "Link to GreyNoise CVE Details Information"

        # Generate ExternalReference
        external_reference = stix2.ExternalReference(
            source_name=self.greynoise_ent_name,
            url=f"https://viz.greynoise.io/cves/{data['id']}",
            external_id=data["id"],
            description=description,
        )
        return [external_reference]

    def _generate_stix_note(self, stix_entity, data: dict):
        today = datetime.today().strftime("%Y-%m-%d")

        content = (
            f"### GreyNoise Vulnerability - Exploitation Activity as of {today}\n\n"
        )
        content += "| Key                                                | Value |\n"
        content += (
            "| --------------------------------------------------- | ---------- |\n"
        )
        content += (
            f"| Activity Seen | {data['exploitation_activity']['activity_seen']} |\n"
        )
        content += f"| Benign IP Count - Last Day | {data['exploitation_activity']['benign_ip_count_1d']} |\n"
        content += f"| Benign IP Count - Last 10 Days | {data['exploitation_activity']['benign_ip_count_10d']} |\n"
        content += f"| Benign IP Count - Last 30 Days | {data['exploitation_activity']['benign_ip_count_30d']} |\n"
        content += f"| Threat IP Count - Last Day | {data['exploitation_activity']['threat_ip_count_1d']} |\n"
        content += f"| Threat IP Count - Last 10 Days | {data['exploitation_activity']['threat_ip_count_10d']} |\n"
        content += f"| Threat IP Count - Last 30 Days | {data['exploitation_activity']['threat_ip_count_30d']} |\n"

        note = stix2.Note(
            type="note",
            id=self.helper.api.note.generate_id(
                created=self.helper.api.stix2.format_date(), content=content
            ),
            object_refs=stix_entity["id"],
            content=content,
            created_by_ref=self.greynoise_identity["id"],
            custom_properties={
                "note_types": ["external"],
            },
        )
        self.stix_objects.append(note)

    def _generate_stix_software(self, stix_entity, data: dict):
        product = data["details"].get("product", "Unknown")
        vendor_name = data["details"].get("vendor", "Unknown")
        created = datetime.today()

        if product == "":
            product = "Unknown"
        if vendor_name == "":
            vendor_name = "Unknown"

        stix_org = stix2.Identity(
            id=Identity.generate_id(vendor_name, "organization"),
            name=f"{vendor_name}",
            identity_class="organization",
            description="Software Vendor",
            created_by_ref=self.greynoise_identity["id"],
            created=created,
            allow_custom=True,
            custom_properties={"x_opencti_organization_type": "vendor"},
        )
        self.stix_objects.append(stix_org)
        org_id = stix_org["id"]

        stix_software = stix2.Software(
            name=f"{product}",
            vendor=f"{vendor_name}",
            allow_custom=True,
            custom_properties={
                "created_by_ref": self.greynoise_identity["id"],
            },
        )
        self.stix_objects.append(stix_software)
        software_id = stix_software["id"]

        software_vendor_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to", software_id, org_id, created
            ),
            relationship_type="related-to",
            description="This software is maintained by",
            source_ref=f"{software_id}",
            target_ref=f"{org_id}",
            confidence=100,
            created_by_ref=self.greynoise_identity["id"],
        )
        self.stix_objects.append(software_vendor_relationship)

        software_vuln_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id("related-to", software_id, org_id),
            relationship_type="has",
            source_ref=f"{software_id}",
            target_ref=stix_entity["id"],
            confidence=100,
            created_by_ref=self.greynoise_identity["id"],
        )
        self.stix_objects.append(software_vuln_relationship)

    def _generate_greynoise_stix_identity(self):
        """
        This method create and adds in "self.stix_objects" the "Identity (organization)" of GreyNoise in Stix2 format,
        its full name is configurable in the environment variable.
        """

        # Generate "GreyNoise Sensor" Identity
        self.greynoise_identity = stix2.Identity(
            id=Identity.generate_id(self.greynoise_ent_name, "organization"),
            name=self.greynoise_ent_name,
            description=f"Connector Enrichment {self.greynoise_ent_name}",
            identity_class="organization",
        )
        self.stix_objects.append(self.greynoise_identity)

    def _generate_stix_vulnerability(self, data: dict, labels, external_reference):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "vulnerability"
        provided by GreyNoise in Stix2 format.
        """
        kev = False
        if (
            "cisa_kev_date_added" in data["timeline"]
            and data["timeline"]["cisa_kev_date_added"]
        ):
            kev = True

        # Generate Vulnerability
        stix_vulnerability = stix2.Vulnerability(
            id=Vulnerability.generate_id(data["id"]),
            name=data["id"],
            created_by_ref=self.greynoise_identity["id"],
            allow_custom=True,
            labels=labels,
            external_references=external_reference,
            description=data["details"].get("vulnerability_description", ""),
            custom_properties={
                "x_opencti_cvss_base_score": data["details"].get("cve_cvss_score", 0),
                "x_opencti_cvss_attack_vector": data["exploitation_details"].get(
                    "attack_vector", ""
                ),
                "x_opencti_cisa_kev": kev,
                "x_opencti_epss_score": data["exploitation_details"].get(
                    "epss_score", 0
                ),
            },
        )
        self.stix_objects.append(stix_vulnerability)

    def _generate_stix_bundle(self, data: dict, stix_entity: dict) -> str:
        """
        This method create a bundle in Stix2 format.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param stix_entity: A parameter that contains all the IPv4 information in OpenCTI.
        :return: str bundle
        """

        self.stix_entity = stix_entity
        self._generate_greynoise_stix_identity()

        self.helper.connector_logger.info(
            "[CONNECTOR] Vulnerability, has been identified by GreyNoise and generation of the Stix bundle is in "
            "progress.",
            {"Vulnerability": stix_entity["name"]},
        )

        # Generate Stix Object for bundle
        labels = self._process_labels(data)
        external_reference = self._generate_stix_external_reference(data)

        if "exploitation_activity" in data:
            self._generate_stix_note(stix_entity, data)
        self._generate_stix_software(stix_entity, data)
        self._generate_stix_vulnerability(data, labels, external_reference)

        uniq_bundles_objects = list(
            {obj["id"]: obj for obj in self.stix_objects}.values()
        )

        self.helper.connector_logger.info(
            "[CONNECTOR] For this CVE, the number of Stix bundle(s) that will be enriched.",
            {
                "Vulnerability": stix_entity["name"],
                "Stix_bundle_length": len(uniq_bundles_objects),
            },
        )

        stix2_bundle = self.helper.stix2_create_bundle(uniq_bundles_objects)
        return stix2_bundle

    def _process_message(self, data: Dict) -> str:
        # Security to limit playbook triggers to something other than the scope initial
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_splited = data["entity_id"].split("--")
        entity_type = entity_splited[0].lower()

        if not self.check_api_key():
            self.helper.log_error(
                "GreyNoise API Key is NOT valid. Update to Enterprise API key to use this connector."
            )
            raise ValueError(
                "GreyNoise API Key is NOT valid. Update to Enterprise API key to use this connector."
            )

        if entity_type in scopes:
            # OpenCTI entity information retrieval
            stix_entity = data["stix_entity"]
            opencti_entity = data["enrichment_entity"]
            self.stix_objects = data["stix_objects"]

            is_valid_max_tlp = self._extract_and_check_markings(opencti_entity)
            if not is_valid_max_tlp:
                raise ValueError(
                    "[ERROR] Do not send any data, TLP of the observable is greater than MAX TLP, "
                    "the connector does not has access to this observable, please check the group of the connector user"
                )

            # Extract Value from opencti entity data
            opencti_entity_value = stix_entity["name"]

            try:
                # Get "CVE Context" GreyNoise API Response
                # https://docs.greynoise.io/reference/get_v1-cve-cve-id
                self.helper.connector_logger.info(
                    f"Get CVE context for: {opencti_entity_value}"
                )
                session = GreyNoise(
                    api_key=self.greynoise_key, integration_name=self.integration_name
                )

                json_data = session.cve(opencti_entity_value)

                if "CVE not found" == json_data:
                    stix_bundle = self.helper.stix2_create_bundle(self.stix_objects)
                    bundles_sent = self.helper.send_stix2_bundle(stix_bundle)
                    return (
                        "[CONNECTOR] No CVE found. Original Vulnerability sent:  "
                        + str(len(bundles_sent))
                        + " stix bundle(s) for worker import"
                    )
                else:
                    # Generate a stix bundle
                    stix_bundle = self._generate_stix_bundle(json_data, stix_entity)

                    # Send stix2 bundle
                    bundles_sent = self.helper.send_stix2_bundle(stix_bundle)

                return (
                    "[CONNECTOR] Sent "
                    + str(len(bundles_sent))
                    + " stix bundle(s) for worker import"
                )

            except Exception as e:
                # Handling other unexpected exceptions
                raise ValueError(
                    "[ERROR] Unexpected Error occurred :", {"Exception": str(e)}
                )
        else:
            return self.helper.connector_logger.info(
                "[INFO] The trigger does not concern the initial scope found in the config connector, "
                "maybe choose a more specific filter in the playbook",
                {"entity_id": data["entity_id"]},
            )

    # Start the main loop
    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        greyNoiseInstance = GreyNoiseVulnConnector()
        greyNoiseInstance.start()
    except Exception:
        traceback.print_exc()
        exit(1)
