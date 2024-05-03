import json
import os
from datetime import datetime
from typing import Dict

import pycountry
import stix2
import yaml
from dateutil.parser import parse
from greynoise import GreyNoise
from pycti import (
    Identity,
    Indicator,
    Location,
    Malware,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    StixSightingRelationship,
    ThreatActor,
    Tool,
    Vulnerability,
    get_config_variable,
)


class GreyNoiseConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
        self.greynoise_key = get_config_variable(
            "GREYNOISE_KEY", ["greynoise", "key"], config
        )
        self.max_tlp = get_config_variable(
            "GREYNOISE_MAX_TLP", ["greynoise", "max_tlp"], config
        )
        self.sighting_not_seen = get_config_variable(
            "GREYNOISE_SIGHTING_NOT_SEEN", ["greynoise", "sighting_not_seen"], config
        )
        self.greynoise_ent_name = get_config_variable(
            "GREYNOISE_NAME", ["greynoise", "name"], config
        )
        self.greynoise_ent_desc = get_config_variable(
            "GREYNOISE_DESCRIPTION", ["greynoise", "description"], config
        )
        self.default_score = get_config_variable(
            "GREYNOISE_DEFAULT_SCORE",
            ["greynoise", "default_score"],
            config,
            True,
        )

        # Define variables
        self._CONNECTOR_RUN_INTERVAL_SEC = 60 * 60
        self.tlp = None
        self.stix_objects = []

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
                    api_key=self.greynoise_key, integration_name="opencti-enricher-v3.1"
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
                "[ERROR] The label could not be created. If your connector does not have the permission to create labels, "
                "please create it manually before launching",
                {"name_label": name_label},
            )
        else:
            self.all_labels.append(new_custom_label["value"])

    @staticmethod
    def _get_match(data, key, value):
        return next((x for x in data if x[key] == value), None)

    def _process_labels(self, data: dict, data_tags: dict) -> tuple:
        """
        This method allows you to start the process of creating labels and recovering associated malware.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param data_tags: A parameter that contains all the data relating to the existing tags in GreyNoise
        :return: A tuple (all labels, all malwares)
        """

        self.all_labels = []
        all_malwares = []
        entity_tags = data["tags"]

        if data["classification"] == "benign":
            # Create label GreyNoise "benign"
            self._create_custom_label("gn-classification: benign", "#06c93a")
            # Include additional label "benign-actor"
            self._create_custom_label(f"gn-benign-actor: {data['actor']} ", "#06c93a")

        elif data["classification"] == "unknown":
            # Create label GreyNoise "unknown"
            self._create_custom_label("gn-classification: unknown", "#a6a09f")

        elif data["classification"] == "malicious":
            # Create label GreyNoise "malicious"
            self._create_custom_label("gn-classification: malicious", "#ff8178")

        if data["bot"] is True:
            # Create label for "Known Bot Activity"
            self._create_custom_label("Known BOT Activity", "#7e4ec2")

        if data["metadata"]["tor"] is True:
            # Create label for "Known Tor Exit Node"
            self._create_custom_label("Known TOR Exit Node", "#7e4ec2")

        # Create all Labels in entity_tags
        for tag in entity_tags:
            tag_details_matching = self._get_match(data_tags["metadata"], "name", tag)
            if tag_details_matching is not None:
                tag_details = tag_details_matching
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] The tag was created, but its details were not correctly recognized by GreyNoise, which is often related to a name problem.",
                    {"Tag_name": tag},
                )
                self.all_labels.append(tag)
                continue

            # Create red label when malicious intent and type not category worm and activity
            if tag_details["intention"] == "malicious" and tag_details[
                "category"
            ] not in ["worm", "activity"]:
                self._create_custom_label(f"{tag}", "#ff8178")

            # If category is worm, prepare malware object
            elif tag_details["category"] == "worm":
                malware_worm = {
                    "name": f"{tag}",
                    "description": f"{tag_details['description']}",
                    "type": "worm",
                }
                all_malwares.append(malware_worm)
                self.all_labels.append(tag)

            # If category is malicious and activity, prepare malware object
            elif (
                tag_details["intention"] == "malicious"
                and tag_details["category"] == "activity"
            ):
                malware_malicious_activity = {
                    "name": f"{tag}",
                    "description": f"{tag_details['description']}",
                    "type": "malicious_activity",
                }
                all_malwares.append(malware_malicious_activity)
                self.all_labels.append(tag)

            else:
                # Create white label otherwise
                self._create_custom_label(f"{tag}", "#ffffff")

        return self.all_labels, all_malwares

    def _generate_stix_external_reference(
        self, data: dict, sighting_not_seen: bool = False
    ) -> list:
        """
        This method allows you to create an external reference in Stix2 format.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param sighting_not_seen: This parameter is a boolean that corresponds to the configuration of
                                  sighting_not_seen, which aims to know if the user wants to create a sighting at 0.
        :return: list -> ExternalReference (Stix2 format)
        """

        description = (
            "This IP has not yet been identified by GreyNoise, meaning it has not been seen mass scanning "
            "the internet nor does it belong to a business service that we monitor."
            if sighting_not_seen is True
            else f'[{data["metadata"]["country_code"]}] - {data["metadata"]["city"]}'
        )

        # Generate ExternalReference
        external_reference = stix2.ExternalReference(
            source_name=self.greynoise_ent_name,
            url=f"https://viz.greynoise.io/ip/{data['ip']}",
            external_id=data["ip"],
            description=description,
        )
        return [external_reference]

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

    def _generate_other_stix_identity_with_relationship(self, data: dict):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "Identity (organization)"
        provided by GreyNoise in Stix2 format,

        - Relationship : Observable -> "related-to" -> Organization.
        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        """

        organization = data["metadata"]["organization"]

        # Generate other Identity
        stix_organization = stix2.Identity(
            id=Identity.generate_id(organization, "organization"),
            name=organization,
            identity_class="organization",
            created_by_ref=self.greynoise_identity["id"],
        )
        self.stix_objects.append(stix_organization)

        # Generate Relationship : Observable -> "related-to" -> Organization
        observable_to_organization = self._generate_stix_relationship(
            self.stix_entity["id"], "related-to", stix_organization.id
        )
        self.stix_objects.append(observable_to_organization)

    def _generate_stix_asn_with_relationship(self, data: dict):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "Autonomous System Number"
        provided by GreyNoise in Stix2 format,

        - Relationship : observable -> "belongs-to" -> Asn.
        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        """

        # Generate Asn
        entity_asn = data["metadata"]["asn"]
        asn_number = int(data["metadata"]["asn"].replace("AS", ""))
        stix_asn = stix2.AutonomousSystem(
            type="autonomous-system",
            number=asn_number,
            name=entity_asn,
            custom_properties={
                "created_by_ref": self.greynoise_identity["id"],
                "x_opencti_score": self.default_score,
            },
        )
        self.stix_objects.append(stix_asn)

        # Generate Relationship : observable -> "belongs-to" -> Asn
        observable_to_asn = self._generate_stix_relationship(
            self.stix_entity["id"], "belongs-to", stix_asn.id
        )
        self.stix_objects.append(observable_to_asn)

    def _generate_stix_location_with_relationship(self, data: dict):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "Location (City + Country)"
        provided by GreyNoise in Stix2 format.

        - Relationships : (observable -> "located-at" -> city) and (city -> "located-at" -> country)
        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        """

        country = pycountry.countries.get(alpha_2=data["metadata"]["country_code"])
        country_name = (
            country.official_name if hasattr(country, "official_name") else country.name
        )

        # Generate City Location
        stix_city_location = stix2.Location(
            id=Location.generate_id(data["metadata"]["city"], "City"),
            name=data["metadata"]["city"],
            country=country_name,
            custom_properties={"x_opencti_location_type": "City"},
        )
        self.stix_objects.append(stix_city_location)

        # Generate Relationship : observable -> "located-at" -> city
        observable_to_city = self._generate_stix_relationship(
            self.stix_entity["id"], "located-at", stix_city_location.id
        )
        self.stix_objects.append(observable_to_city)

        # Generate Country Location
        stix_country_location = stix2.Location(
            id=Location.generate_id(country.name, "Country"),
            name=country_name,
            country=country_name,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [data["metadata"]["country_code"]],
            },
        )
        self.stix_objects.append(stix_country_location)

        # Generate Relationship : city -> "located-at" -> country
        city_to_country = self._generate_stix_relationship(
            stix_city_location.id, "located-at", stix_country_location.id
        )
        self.stix_objects.append(city_to_country)

    def _generate_stix_vulnerability_with_relationship(self, data: dict):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "vulnerability"
        provided by GreyNoise in Stix2 format.

        - Relationship : observable -> "related-to" -> vulnerability
        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        """

        if "cve" in data:
            entity_vulns = data["cve"]
            for vuln in entity_vulns:
                # Generate Vulnerability
                stix_vulnerability = stix2.Vulnerability(
                    id=Vulnerability.generate_id(vuln),
                    name=vuln,
                    created_by_ref=self.greynoise_identity["id"],
                    allow_custom=True,
                )
                self.stix_objects.append(stix_vulnerability)

                # Generate Relationship : observable -> "related-to" -> vulnerability
                observable_to_vulnerability = self._generate_stix_relationship(
                    self.stix_entity["id"],
                    "related-to",
                    stix_vulnerability.id,
                    self.first_seen,
                    self.last_seen,
                )
                self.stix_objects.append(observable_to_vulnerability)

    def _generate_stix_tool_with_relationship(self, data: dict):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "tool"
        provided by GreyNoise in Stix2 format.

        - Relationship : observable -> "related-to" -> tool
        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        """

        if data["vpn"] is True:
            # Generate Tool
            stix_tool = stix2.Tool(
                id=Tool.generate_id(f"VPN: {data['vpn_service']}"),
                name=f"VPN: {data['vpn_service']}",
                labels=["tool"],
                created_by_ref=self.greynoise_identity["id"],
                custom_properties={"x_opencti_aliases": data["vpn_service"]},
                allow_custom=True,
            )
            self.stix_objects.append(stix_tool)

            # Generate Relationship : observable -> "related-to" -> tool
            observable_to_tool = self._generate_stix_relationship(
                self.stix_entity["id"],
                "related-to",
                stix_tool.id,
                self.first_seen,
                self.last_seen,
            )
            self.stix_objects.append(observable_to_tool)

    def _generate_stix_sighting(
        self,
        external_reference: list,
        stix_indicator: dict,
        sighting_not_seen: bool = False,
    ):
        """
        This method creates a sighting.

        - If the IPv4 is known by GreyNoise:

          - Create a `sighting` from the IPv4 observable to the GreyNoise entity with `count=1`

        - If the IPv4 is not knew by GreyNoise:

          - if `GREYNOISE_SIGHTING_NOT_SEEN=true`: create a `sighting` from the IPv4 observable to the
            GreyNoise entity with `count=0`
          - if `GREYNOISE_SIGHTING_NOT_SEEN=false`: do nothing.

        :param external_reference: This parameter contains the list external reference associated with the IPv4.
        :param sighting_not_seen: This parameter is a boolean that corresponds to the configuration of
                                  sighting_not_seen, which aims to know if the user wants to create a sighting at 0.
        """

        default_now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        stix_sighting = stix2.Sighting(
            id=StixSightingRelationship.generate_id(
                self.stix_entity["id"],
                self.greynoise_identity["id"],
                default_now if sighting_not_seen is True else self.first_seen,
                default_now if sighting_not_seen is True else self.last_seen,
            ),
            first_seen=default_now if sighting_not_seen is True else self.first_seen,
            last_seen=default_now if sighting_not_seen is True else self.last_seen,
            count=0 if sighting_not_seen is True else 1,
            description=self.greynoise_ent_desc,
            created_by_ref=self.greynoise_identity["id"],
            sighting_of_ref=stix_indicator["id"],
            where_sighted_refs=[self.greynoise_identity["id"]],
            external_references=external_reference,
            object_marking_refs=stix2.TLP_WHITE,
            custom_properties={
                "x_opencti_sighting_of_ref": self.stix_entity["id"],
                "x_opencti_negative": True,
            },
        )
        self.stix_objects.append(stix_sighting)

    def _generate_stix_malware_with_relationship(self, malwares: list):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "malware"
        provided by GreyNoise in Stix2 format.

        - Relationship : observable -> "related-to" -> malware
        :param malwares: This parameter contains a list of all malwares associated with the IPv4 of the searched
                         observable, whose malwares is retrieved when comparing labels and data_tags.
        """

        for malware in malwares:
            stix_malware = stix2.Malware(
                id=Malware.generate_id(malware["name"]),
                created_by_ref=self.greynoise_identity["id"],
                name=malware["name"],
                description=malware["description"],
                is_family=False,
                malware_types=malware["type"] if malware["type"] == "worm" else None,
                created=self.first_seen,
            )
            self.stix_objects.append(stix_malware)

            # Generate Relationship : observable -> "related-to" -> malware
            observable_to_malware = self._generate_stix_relationship(
                self.stix_entity["id"],
                "related-to",
                stix_malware.id,
                self.first_seen,
                self.last_seen,
            )
            self.stix_objects.append(observable_to_malware)

    def _generate_stix_threat_actor_with_relationship(self, data: dict):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "Threat Actor"
        provided by GreyNoise in Stix2 format.

        - Relationship : observable -> "related-to" -> threat actor
        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        """

        # Create threat actor for non-benign when known
        if (
            data["actor"]
            and data["actor"] != "unknown"
            and data["classification"] != "benign"
        ):
            # Generate Threat Actor
            stix_threat_actor = stix2.ThreatActor(
                id=ThreatActor.generate_id(data["actor"]),
                name=data["actor"],
                created_by_ref=self.greynoise_identity["id"],
            )
            self.stix_objects.append(stix_threat_actor)

            # Generate Relationship : observable -> "related-to" -> threat actor
            observable_to_threat_actor = self._generate_stix_relationship(
                self.stix_entity["id"],
                "related-to",
                stix_threat_actor.id,
                self.first_seen,
                self.last_seen,
            )
            self.stix_objects.append(observable_to_threat_actor)

    def _generate_stix_indicator_with_relationship(
        self, data: dict, detection: bool, external_reference: list, labels: list = None
    ) -> dict:
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "Indicator"
        in Stix2 format.

        - Relationship : Indicator -> "based-on" -> Observable
        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param detection: If sighting_not_seen is true, then this detection parameter is false and vice versa.
        :param external_reference: This parameter contains the list external reference associated with the IPv4.
        :param labels: This parameter contains a list of all labels associated with the IPv4.
        :return: dict
        """

        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Generate Indicator
        stix_indicator = stix2.Indicator(
            id=Indicator.generate_id(data["ip"]),
            name=data["ip"],
            labels=labels if detection is True else [],
            pattern=f"[ipv4-addr:value = '{data['ip']}']",
            created_by_ref=self.greynoise_identity["id"],
            external_references=external_reference,
            valid_from=now,
            custom_properties={
                "pattern_type": "stix",
                "x_opencti_score": self.default_score,
                "x_opencti_main_observable_type": "IPv4-Addr",
                "detection": True if detection is True else False,
            },
        )
        self.stix_objects.append(stix_indicator)

        # Generate Relationship : Indicator -> "based-on" -> Observable
        indicator_to_observable = self._generate_stix_relationship(
            stix_indicator.id, "based-on", self.stix_entity["id"]
        )
        self.stix_objects.append(indicator_to_observable)

        return stix_indicator

    def _generate_stix_observable(
        self, detection: bool, external_reference: list, labels: list = None
    ):
        """
        This method creates and adds a bundle to "self.stix_objects" the IPv4 associated "Observable"
        in Stix2 format.

        :param detection: If sighting_not_seen is true, then this detection parameter is false and vice versa.
        :param external_reference: This parameter contains the list external reference associated with the IPv4.
        :param labels: This parameter contains a list of all labels associated with the IPv4.
        """

        # Generate Observable
        stix_observable = stix2.IPv4Address(
            id=self.stix_entity["id"],
            type="ipv4-addr",
            value=self.stix_entity["value"],
            custom_properties={
                "x_opencti_external_references": external_reference,
                "x_opencti_score": self.default_score,
                "x_opencti_labels": labels if detection is True else [],
                "x_opencti_created_by_ref": self.greynoise_identity["id"],
            },
        )
        self.stix_objects.append(stix_observable)

    def _generate_stix_bundle(
        self, data: dict, data_tags: dict, stix_entity: dict
    ) -> str:
        """
        This method create a bundle in Stix2 format.

        :param data: A parameter that contains all the data about the IPv4 that was searched for in GreyNoise.
        :param data_tags: A parameter that contains all the data relating to the existing tags in GreyNoise.
        :param stix_entity: A parameter that contains all the IPv4 information in OpenCTI.
        :return: str bundle
        """

        self.stix_entity = stix_entity
        self._generate_greynoise_stix_identity()

        if data["seen"] is False and self.sighting_not_seen is True:
            """
            If the IP has not been identified by GreyNoise, but the user still wants to create a sighting at count=0,
            they can do so by setting the sighting_not_seen variable to "true", in this case we create an external
            reference linked in the sighting.
            """

            self.helper.connector_logger.info(
                "[CONNECTOR] The IPv4 has not been identified, but the creation of the sighting is true",
                {
                    "IPv4": stix_entity["value"],
                    "config_sighting_not_seen": self.sighting_not_seen,
                },
            )

            external_reference = self._generate_stix_external_reference(data, True)
            stix_indicator = self._generate_stix_indicator_with_relationship(
                data, False, external_reference
            )

            self._generate_stix_observable(False, external_reference)
            self._generate_stix_sighting(external_reference, stix_indicator, True)

        else:
            self.helper.connector_logger.info(
                "[CONNECTOR] IPv4, has been identified by GreyNoise and generation of the Stix bundle is in progress.",
                {"IPv4": stix_entity["value"]},
            )

            self.first_seen = parse(data["first_seen"]).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.last_seen = parse(data["last_seen"]).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Generate Stix Object for bundle
            labels, malwares = self._process_labels(data, data_tags)
            external_reference = self._generate_stix_external_reference(data)
            stix_indicator = self._generate_stix_indicator_with_relationship(
                data, True, external_reference, labels
            )

            self._generate_other_stix_identity_with_relationship(data)
            self._generate_stix_asn_with_relationship(data)
            self._generate_stix_location_with_relationship(data)  # City + Country
            self._generate_stix_vulnerability_with_relationship(data)
            self._generate_stix_tool_with_relationship(data)
            self._generate_stix_malware_with_relationship(malwares)
            self._generate_stix_threat_actor_with_relationship(data)
            self._generate_stix_observable(True, external_reference, labels)
            self._generate_stix_sighting(external_reference, stix_indicator, False)

        uniq_bundles_objects = list(
            {obj["id"]: obj for obj in self.stix_objects}.values()
        )

        self.helper.connector_logger.info(
            "[CONNECTOR] For this Ipv4, the number of Stix bundle(s) that will be enriched.",
            {
                "IPv4": stix_entity["value"],
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
            opencti_entity_value = stix_entity["value"]

            try:
                # Get "IP Context" GreyNoise API Response
                # https://docs.greynoise.io/reference/noisecontextip-1
                session = GreyNoise(
                    api_key=self.greynoise_key, integration_name="opencti-enricher-v3.1"
                )

                json_data = session.ip(opencti_entity_value)

                if (
                    "seen" in json_data
                    and json_data["seen"] is False
                    and self.sighting_not_seen is False
                ):
                    raise ValueError(
                        "[API] This IP has not yet been identified by GreyNoise"
                    )

                # Get "Tag Metadata" Greynoise API Response
                # https://docs.greynoise.io/reference/metadata-3

                json_data_tags = session.metadata()

                # Generate a stix bundle
                stix_bundle = self._generate_stix_bundle(
                    json_data, json_data_tags, stix_entity
                )

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
    greyNoiseInstance = GreyNoiseConnector()
    greyNoiseInstance.start()
