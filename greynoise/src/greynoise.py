import os
from time import sleep

import requests
import pycountry
import yaml
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE


class GreyNoiseConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = yaml.load(open(config_file_path), Loader=yaml.FullLoader) if os.path.isfile(config_file_path) else {}
        self.helper = OpenCTIConnectorHelper(config)
        self.greynoise_key = get_config_variable("GREYNOISE_KEY", ["greynoise", "key"], config)
        self.max_tlp = get_config_variable("GREYNOISE_MAX_TLP", ["greynoise", "max_tlp"], config)
        self.spoofable_confidence_level = get_config_variable(
            "GREYNOISE_SPOOFABLE_CONFIDENCE_LEVEL",
            ["greynoise", "spoofable_confidence_level"],
            config,
        )
        self.sighting_not_seen = get_config_variable(
            "GREYNOISE_SIGHTING_NOT_SEEN", ["greynoise", "sighting_not_seen"], config
        )

        self.greynoise_ent_name = get_config_variable("GREYNOISE_NAME", ["greynoise", "name"], config)
        self.greynoise_ent_desc = get_config_variable("GREYNOISE_DESCRIPTION", ["greynoise", "description"], config)
        self.api_url = "https://api.greynoise.io/v2/"
        self.headers = {
            "key": self.greynoise_key,
            "Accept": "application/json",
            "User-Agent": "greynoise-opencti-connector-v1.1",
        }
        self._CONNECTOR_RUN_INTERVAL_SEC = 60 * 60
        self.greynoise_id = None

    def _get_greynoise_id(self) -> int:
        """Get or create a Greynoise entity if not exists"""

        if self.greynoise_id is not None:
            return self.greynoise_id

        greynoise_entity = self.helper.api.stix_domain_object.get_by_stix_id_or_name(name=self.greynoise_ent_name)
        if not greynoise_entity:
            self.helper.log_info(f"Create {self.greynoise_ent_name}")
            self.greynoise_id = self.helper.api.identity.create(
                type="Organization",
                name=self.greynoise_ent_name,
                description=self.greynoise_ent_desc,
            )["id"]
            return self.greynoise_id
        else:
            self.helper.log_info(f"Cache {self.greynoise_ent_name} id")
            self.greynoise_id = greynoise_entity["id"]
            return self.greynoise_id

    def _call_api(self, observable):
        response = requests.get(
            self.api_url + "noise/context/" + observable["value"],
            headers=self.headers,
        )
        json_data = response.json()

        if response.status_code == 429:
            self.helper.log_info(f"Quota reached, waiting {self._CONNECTOR_RUN_INTERVAL_SEC} seconds.")
            sleep(self._CONNECTOR_RUN_INTERVAL_SEC)
            self._call_api(observable)
            return "Observable processed after quota reached, waiting 1 hour."
        if response.status_code >= 400:
            raise ValueError(response.text)

        self.helper.log_info(f'Start processing observable {observable["observable_value"]}')
        if "ip" in json_data:
            external_reference = self.helper.api.external_reference.create(
                source_name=self.greynoise_ent_name,
                url="https://www.greynoise.io/viz/ip/" + observable["observable_value"],
                update=True,
            )
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=observable["id"], external_reference_id=external_reference["id"]
            )

            if not json_data["seen"]:
                if self.sighting_not_seen:
                    self.helper.api.stix_sighting_relationship.create(
                        fromId=observable["id"],
                        toId=self._get_greynoise_id(),
                        createdBy=self._get_greynoise_id(),
                        description=self.greynoise_ent_desc,
                        confidence=int(self.helper.connect_confidence_level),
                        objectMarking=[TLP_WHITE["id"]],
                        externalReferences=[external_reference["id"]],
                        count=0,
                    )
                    self.helper.log_info("IP not seen.")
                    return "IP not seen."
                else:
                    self.helper.log_info("IP not seen. No sighting created.")
                    return "IP not seen. No sighting created."

            first_seen = parse(json_data["first_seen"]).strftime("%Y-%m-%dT%H:%M:%SZ")
            last_seen = parse(json_data["last_seen"]).strftime("%Y-%m-%dT%H:%M:%SZ")
            confidence = int(
                self.spoofable_confidence_level if json_data["spoofable"] else self.helper.connect_confidence_level
            )
            # parse tags in response to create labels
            if "tags" in json_data:
                # get tag metadata
                tags_response = requests.get(
                    self.api_url + "meta/metadata/",
                    headers=self.headers,
                )
                # find tag details
                for tag in json_data["tags"]:
                    label = {}
                    malware = {}
                    for item in tags_response.json()["metadata"]:
                        if item["name"] == tag:
                            tag_details = item
                            break
                    # create red label when malicious intent and type not cat or activity
                    if tag_details["intention"] == "malicious" and tag_details["category"] not in ["worm", "activity"]:
                        label = self.helper.api.label.create(
                            value=tag,
                            color="#ff8178",
                        )
                    # if worm, create malware object
                    elif tag_details["category"] == "worm":
                        malware = self.helper.api.malware.create(
                            name=tag,
                            description=tag_details["description"],
                            malware_types="worm",
                            first_seen=first_seen,
                            last_seen=last_seen,
                            update=True,
                        )
                    # if malicous activty, create malware object
                    elif tag_details["intention"] == "malicious" and tag_details["category"] == "activity":
                        malware = self.helper.api.malware.create(
                            name=tag,
                            description=tag_details["description"],
                            first_seen=first_seen,
                            last_seen=last_seen,
                            update=True,
                        )
                    # create white label otherwise
                    else:
                        label = self.helper.api.label.create(
                            value=tag,
                            color="#ffffff",
                        )

                    # Add the tag or malware object
                    if label:
                        self.helper.api.stix_cyber_observable.add_label(id=observable["id"], label_id=label["id"])
                    if malware:
                        self.helper.api.stix_core_relationship.create(
                            fromId=observable["id"],
                            toId=malware["id"],
                            relationship_type="related-to",
                            update=True,
                            start_time=first_seen,
                            stop_time=last_seen,
                            confidence=confidence,
                        )
            # track fp for sighting
            x_opencti_negative = False
            # add classification info in tags for clarity
            if json_data.get("classification") == "malicious":
                label = self.helper.api.label.create(
                    value="gn-classification: " + json_data["classification"], color="#ff8178"
                )
                self.helper.api.stix_cyber_observable.add_label(id=observable["id"], label_id=label["id"])
            elif json_data.get("classification") == "unknown":
                label = self.helper.api.label.create(
                    value="gn-classification: " + json_data["classification"], color="#a6a09f"
                )
                self.helper.api.stix_cyber_observable.add_label(id=observable["id"], label_id=label["id"])
            elif json_data.get("classification") == "benign":
                label = self.helper.api.label.create(
                    value="gn-classification: " + json_data["classification"], color="#06c93a"
                )
                # include additional tag for benign actor for clarity
                actor = self.helper.api.label.create(value="gn-benign-actor: " + json_data["actor"], color="#06c93a")
                self.helper.api.stix_cyber_observable.add_label(id=observable["id"], label_id=label["id"])
                self.helper.api.stix_cyber_observable.add_label(id=observable["id"], label_id=actor["id"])
                # set sighting to be FP since benign
                x_opencti_negative = True

            # create threat actor for non-benign when known
            if json_data["actor"] and json_data["actor"] != "unknown" and json_data["classification"] != "benign":
                actor = self.helper.api.threat_actor.create(
                    name=json_data["actor"], first_seen=first_seen, last_seen=last_seen, update=True
                )
                self.helper.api.stix_core_relationship.create(
                    fromId=observable["id"],
                    toId=actor["id"],
                    relationship_type="related-to",
                    update=True,
                    start_time=first_seen,
                    stop_time=last_seen,
                    confidence=confidence,
                )
            # create vulns for known CVEs
            if "cve" in json_data:
                for item in json_data["cve"]:
                    vuln = self.helper.api.vulnerability.create(name=item)
                    self.helper.api.stix_core_relationship.create(
                        fromId=observable["id"],
                        toId=vuln["id"],
                        relationship_type="related-to",
                        update=True,
                        start_time=first_seen,
                        stop_time=last_seen,
                        confidence=confidence,
                    )
            # add VPN tool and relationship
            if json_data.get("vpn"):
                vpn = self.helper.api.tool.create(name="VPN: " + json_data["vpn_service"], update=True)
                self.helper.api.stix_core_relationship.create(
                    fromId=observable["id"],
                    toId=vpn["id"],
                    relationship_type="related-to",
                    update=True,
                    start_time=first_seen,
                    stop_time=last_seen,
                    confidence=confidence,
                )
            # add label for known bot activity
            if json_data.get("bot"):
                label = self.helper.api.label.create(value="Known BOT Activity", color="#7e4ec2", update=True)
                self.helper.api.stix_cyber_observable.add_label(id=observable["id"], label_id=label["id"])
            # add label for Tor Exit Node Status
            if json_data["metadata"].get("tor"):
                label = self.helper.api.label.create(value="Known TOR Exit Node", color="#7e4ec2", update=True)
                self.helper.api.stix_cyber_observable.add_label(id=observable["id"], label_id=label["id"])

            # create and update city/country objects and relationships
            country = pycountry.countries.get(alpha_2=json_data["metadata"]["country_code"])
            if country and json_data["metadata"]["city"]:
                country_object = self.helper.api.location.create(
                    name=country.name,
                    type="Country",
                    country=country.official_name if hasattr(country, "official_name") else country.name,
                    custom_properties={
                        "x_opencti_location_type": "Country",
                        "x_opencti_aliases": [
                            country.official_name if hasattr(country, "official_name") else country.name
                        ],
                    },
                )
                city_object = self.helper.api.location.create(
                    name=json_data["metadata"]["city"],
                    type="City",
                    country=country.official_name if hasattr(country, "official_name") else country.name,
                    custom_properties={"x_opencti_location_type": "City"},
                )
                self.helper.api.stix_core_relationship.create(
                    fromId=city_object["id"],
                    toId=country_object["id"],
                    relationship_type="located-at",
                    update=True,
                )
                self.helper.api.stix_core_relationship.create(
                    fromId=observable["id"],
                    toId=city_object["id"],
                    relationship_type="located-at",
                    update=True,
                    confidence=confidence,
                )

            self.helper.api.stix_sighting_relationship.create(
                fromId=observable["id"],
                toId=self._get_greynoise_id(),
                createdBy=self._get_greynoise_id(),
                description=self.greynoise_ent_desc,
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=confidence,
                objectMarking=[TLP_WHITE["id"]],
                externalReferences=[external_reference["id"]],
                count=1,
                x_opencti_negative=x_opencti_negative,
            )
            return f'IPv4 {observable["observable_value"]} found on GreyNoise, knowledge attached.'

    def _process_message(self, data):
        self.helper.log_info("process data: " + str(data))
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError("Do not send any data, TLP of the observable is greater than MAX TLP")

        if observable["entity_type"] == "IPv4-Addr":
            return self._call_api(observable)

    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    greyNoiseInstance = GreyNoiseConnector()
    greyNoiseInstance.start()
