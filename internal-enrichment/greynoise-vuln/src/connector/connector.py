from datetime import datetime
from typing import Dict

import stix2
from connector.settings import ConnectorSettings
from greynoise.api import APIConfig, GreyNoise
from pycti import (
    Identity,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    Vulnerability,
)


class GreyNoiseVulnConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.greynoise_key = self.config.greynoise_vuln.key.get_secret_value()
        self.max_tlp = self.config.greynoise_vuln.max_tlp
        self.greynoise_ent_name = self.config.greynoise_vuln.name
        self.greynoise_ent_desc = self.config.greynoise_vuln.description

        # Define variables
        self.stix_objects = []
        self.integration_name = "opencti-vuln-enricher-v2.0"

    def _extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Extract TLP and raise if the entity's marking exceeds max_tlp.

        :param opencti_entity: Parameter that contains all information about the entity,
                               including "objectMarking", the marking that the observable uses.
        """

        tlp = "TLP:AMBER"
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "[ERROR] Do not send any data, TLP of the observable is greater than MAX TLP, "
                "the connector does not have access to this observable, "
                "please check the group of the connector user"
            )

    def _generate_stix_relationship(
        self,
        source_ref: str,
        stix_core_relationship_type: str,
        target_ref: str,
        start_time: str | None = None,
    ) -> stix2.Relationship:
        """
        This method allows you to create a relationship in Stix2 format.

        :param source_ref: This parameter is the "from" of the relationship.
        :param stix_core_relationship_type: Parameter,
        :param target_ref: This parameter is the "to" of the relationship.
        :param start_time: This parameter is the start of the relationship. Value not required, None by default.
        :return: A dict
        """

        return stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                stix_core_relationship_type, source_ref, target_ref
            ),
            relationship_type=stix_core_relationship_type,
            source_ref=source_ref,
            start_time=start_time,
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

    def _process_labels(self, data: dict) -> list:
        """
        This method allows you to start the process of creating labels and recovering associated malware.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :return: A list of all labels
        """

        self.all_labels = []

        if data.get("exploitation_activity", {}).get("activity_seen"):
            # Create label GreyNoise for activity_seen:true
            self._create_custom_label("gn-activity-seen", "#a6a09f")

        if (
            data.get("exploitation_stats", {}).get("number_of_available_exploits", 0)
            >= 1
        ):
            # Create label GreyNoise "malicious"
            self._create_custom_label("gn-exploits-available", "#ff8178")

        if (
            data.get("exploitation_stats", {}).get(
                "number_of_threat_actors_exploiting_vulnerability", 0
            )
            >= 1
        ):
            # Create label GreyNoise "malicious"
            self._create_custom_label("gn-threat-actors-exploiting", "#ff8178")

        return self.all_labels

    def _generate_stix_external_reference(self, data: dict) -> list:
        """
        This method allows you to create an external reference in Stix2 format.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
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

    def _generate_stix_note(self, stix_entity: dict, data: dict):
        today = datetime.today().strftime("%Y-%m-%d")

        exploitation_activity = data["exploitation_activity"]

        content = (
            f"### GreyNoise Vulnerability - Exploitation Activity as of {today}\n\n"
            "| Key                                                | Value |\n"
            "| --------------------------------------------------- | ---------- |\n"
            f"| Activity Seen | {exploitation_activity['activity_seen']} |\n"
            f"| Benign IP Count - Last Day | {exploitation_activity['benign_ip_count_1d']} |\n"
            f"| Benign IP Count - Last 10 Days | {exploitation_activity['benign_ip_count_10d']} |\n"
            f"| Benign IP Count - Last 30 Days | {exploitation_activity['benign_ip_count_30d']} |\n"
            f"| Threat IP Count - Last Day | {exploitation_activity['threat_ip_count_1d']} |\n"
            f"| Threat IP Count - Last 10 Days | {exploitation_activity['threat_ip_count_10d']} |\n"
            f"| Threat IP Count - Last 30 Days | {exploitation_activity['threat_ip_count_30d']} |\n"
        )

        note = stix2.Note(
            type="note",
            id=Note.generate_id(created=None, content=content),
            object_refs=stix_entity["id"],
            content=content,
            created_by_ref=self.greynoise_identity["id"],
            custom_properties={
                "note_types": ["external"],
            },
        )
        self.stix_objects.append(note)

    def _generate_stix_software(self, stix_entity: dict, data: dict):
        created = datetime.today()
        product = data["details"].get("product") or "Unknown"
        vendor_name = data["details"].get("vendor") or "Unknown"

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
            source_ref=software_id,
            target_ref=org_id,
            created_by_ref=self.greynoise_identity["id"],
        )
        self.stix_objects.append(software_vendor_relationship)

        software_vuln_relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id("has", software_id, stix_entity["id"]),
            relationship_type="has",
            source_ref=software_id,
            target_ref=stix_entity["id"],
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

    def _generate_stix_vulnerability(
        self, data: dict, labels: list, external_reference: list
    ):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "vulnerability"
        provided by GreyNoise in Stix2 format.
        """
        kev = bool(data.get("timeline", {}).get("cisa_kev_date_added"))

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

    def _generate_stix_bundle(self, data: dict, stix_entity: dict) -> str | None:
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

        # Deduplicate STIX objects by ID (last occurrence wins)
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
        entity_parts = data["entity_id"].split("--")
        entity_type = entity_parts[0].lower()

        if entity_type in scopes:
            # OpenCTI entity information retrieval
            stix_entity = data["stix_entity"]
            opencti_entity = data["enrichment_entity"]
            self.stix_objects = data["stix_objects"]

            self._extract_and_check_markings(opencti_entity)

            # Extract Value from opencti entity data
            opencti_entity_value = stix_entity["name"]

            try:
                # Get "CVE Context" GreyNoise API Response
                # https://docs.greynoise.io/reference/get_v1-cve-cve-id
                self.helper.connector_logger.info(
                    f"Get CVE context for: {opencti_entity_value}"
                )
                api_config = APIConfig(
                    api_key=self.greynoise_key, integration_name=self.integration_name
                )
                session = GreyNoise(api_config)

                json_data = session.cve(opencti_entity_value)

                if "CVE not found" == json_data:
                    stix_bundle = self.helper.stix2_create_bundle(self.stix_objects)
                    bundles_sent = self.helper.send_stix2_bundle(
                        stix_bundle,
                        cleanup_inconsistent_bundle=True,
                    )
                    return (
                        "[CONNECTOR] No CVE found. Original Vulnerability sent:  "
                        f"{len(bundles_sent)} stix bundle(s) for worker import"
                    )
                else:
                    # Generate a stix bundle
                    stix_bundle = self._generate_stix_bundle(json_data, stix_entity)

                    # Send stix2 bundle
                    bundles_sent = self.helper.send_stix2_bundle(
                        stix_bundle,
                        cleanup_inconsistent_bundle=True,
                    )

                return (
                    f"[CONNECTOR] Sent {len(bundles_sent)} stix bundle(s) "
                    "for worker import"
                )

            except Exception as e:
                # Handling other unexpected exceptions
                raise ValueError(
                    "[ERROR] Unexpected Error occurred :", {"Exception": str(e)}
                )
        else:
            self.helper.connector_logger.info(
                "[INFO] The trigger does not concern the initial scope found in the config connector, "
                "maybe choose a more specific filter in the playbook",
                {"entity_id": data["entity_id"], "event_type": data.get("event_type")},
            )
            if not data.get("event_type"):
                self.helper.send_stix2_bundle(
                    self.helper.stix2_create_bundle(data["stix_objects"]),
                    cleanup_inconsistent_bundle=True,
                )
            return "[INFO] Not in scope, original bundle returned unchanged"

    def process_message(self, data: Dict) -> str:
        try:
            return self._process_message(data)
        except Exception as e:
            self.helper.connector_logger.error(
                "[CONNECTOR] An unexpected error occurred",
                {"error_message": str(e)},
            )
            # If an error occurs, send the original stix objects back
            self.helper.send_stix2_bundle(
                self.helper.stix2_create_bundle(data["stix_objects"]),
                cleanup_inconsistent_bundle=True,
            )
            raise

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
