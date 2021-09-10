import datetime
import json
import os
import requests
import yaml
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils, get_config_variable
from stix2 import (
    Bundle,
    File,
    Indicator,
    Identity,
    MarkingDefinition,
    Relationship,
)
from time import sleep
from typing import Optional


class VirusTotalConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.token = get_config_variable(
            "VIRUSTOTAL_TOKEN", ["virustotal", "token"], config
        )
        self.max_tlp = get_config_variable(
            "VIRUSTOTAL_MAX_TLP", ["virustotal", "max_tlp"], config
        )
        self.api_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.token,
            "accept": "application/json",
            "content-type": "application/json",
        }
        self._CONNECTOR_RUN_INTERVAL_SEC = 60 * 60

    def _create_yara_indicator(
        self, yara: dict, valid_from: Optional[int] = None
    ) -> Indicator:
        """Create an indicator containing the YARA results from VirusTotal."""
        valid_from_date = (
            datetime.datetime.min
            if valid_from is None
            else datetime.datetime.utcfromtimestamp(valid_from)
        )
        source = yara.get("source", "No source provided")
        ruleset_id = yara.get("ruleset_id", "No ruleset id provided")
        return self.helper.api.indicator.create(
            name=yara.get("rule_name", "No rulename provided"),
            description=json.dumps(
                {
                    "description": yara.get("description", "No description provided"),
                    "author": yara.get("author", "No author provided"),
                    "source": yara.get("source", "No source provided"),
                    "ruleset_id": ruleset_id,
                    "ruleset_name": yara.get(
                        "ruleset_name", "No ruleset name provided"
                    ),
                }
            ),
            pattern=f"[YARA] {ruleset_id} full rule available on {source}",
            pattern_type="virustotal-yara",
            valid_from=self.helper.api.stix2.format_date(valid_from_date),
            x_opencti_main_observable_type="StixFile",
        )

    def _process_file(self, observable):
        response = requests.request(
            "GET",
            self.api_url + "/files/" + observable["observable_value"],
            headers=self.headers,
        )
        json_data = json.loads(response.text)
        if "error" in json_data:
            if json_data["error"]["message"] == "Quota exceeded":
                self.helper.log_info("Quota reached, waiting 1 hour.")
                sleep(self._CONNECTOR_RUN_INTERVAL_SEC)
            elif "not found" in json_data["error"]["message"]:
                self.helper.log_info("File not found on VirusTotal.")
                return "File not found on VirusTotal."
            else:
                raise ValueError(json_data["error"]["message"])
        if "data" in json_data:
            data = json_data["data"]
            attributes = data["attributes"]
            # Update the current observable
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=observable["id"], key="hashes.MD5", value=attributes["md5"]
            )
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=final_observable["id"], key="hashes.SHA-1", value=attributes["sha1"]
            )
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=final_observable["id"],
                key="hashes.SHA-256",
                value=attributes["sha256"],
            )
            if observable["entity_type"] == "StixFile":
                self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    key="size",
                    value=str(attributes["size"]),
                )
                if observable["name"] is None and len(attributes["names"]) > 0:
                    self.helper.api.stix_cyber_observable.update_field(
                        id=final_observable["id"],
                        key="name",
                        value=attributes["names"][0],
                    )
                    del attributes["names"][0]

            if len(attributes["names"]) > 0:
                self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    key="x_opencti_additional_names",
                    value=attributes["names"],
                )

            # Create external reference
            external_reference = self.helper.api.external_reference.create(
                source_name="VirusTotal",
                url="https://www.virustotal.com/gui/file/" + attributes["sha256"],
                description=attributes["magic"],
            )

            # Create tags
            for tag in attributes["tags"]:
                tag_vt = self.helper.api.label.create(value=tag, color="#0059f7")
                self.helper.api.stix_cyber_observable.add_label(
                    id=final_observable["id"], label_id=tag_vt["id"]
                )

            self.helper.api.stix_cyber_observable.add_external_reference(
                id=final_observable["id"],
                external_reference_id=external_reference["id"],
            )

            if "crowdsourced_yara_results" in attributes:
                self.helper.log_info("[VirusTotal] adding yara results to file.")

                # Add YARA results
                yaras = [
                    self._create_yara_indicator(
                        yara, attributes.get("creation_date", None)
                    )
                    for yara in attributes["crowdsourced_yara_results"]
                ]

                self.helper.log_debug(f"[VirusTotal] Indicators created: {yaras}")

                # Create the relationships (`related-to`) between the yaras and the file.
                for yara in yaras:
                    self.helper.api.stix_core_relationship.create(
                        fromId=final_observable["id"],
                        toId=yara["id"],
                        relationship_type="related-to",
                    )

            return "File found on VirusTotal, knowledge attached."

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        return self._process_file(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    virusTotalInstance = VirusTotalConnector()
    virusTotalInstance.start()
