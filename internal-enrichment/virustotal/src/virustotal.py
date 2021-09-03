import json
import os
import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from time import sleep


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
                id=observable["id"],
                input={"key": "hashes.MD5", "value": attributes["md5"]},
            )
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=final_observable["id"],
                input={"key": "hashes.SHA-1", "value": attributes["sha1"]},
            )
            final_observable = self.helper.api.stix_cyber_observable.update_field(
                id=final_observable["id"],
                input={"key": "hashes.SHA-256", "value": attributes["sha256"]},
            )
            if observable["entity_type"] == "StixFile":
                self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={"key": "size", "value": str(attributes["size"])},
                )
                if observable["name"] is None and len(attributes["names"]) > 0:
                    self.helper.api.stix_cyber_observable.update_field(
                        id=final_observable["id"],
                        input={"key": "name", "value": attributes["names"][0]},
                    )
                    del attributes["names"][0]

            if len(attributes["names"]) > 0:
                self.helper.api.stix_cyber_observable.update_field(
                    id=final_observable["id"],
                    input={
                        "key": "x_opencti_additional_names",
                        "value": attributes["names"],
                    },
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
