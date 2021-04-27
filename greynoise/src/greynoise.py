import os
from time import sleep

import requests
import yaml
from dateutil.parser import parse
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE


class GreyNoiseConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.greynoise_key = get_config_variable(
            "GREYNOISE_KEY", ["greynoise", "key"], config
        )
        self.max_tlp = get_config_variable(
            "GREYNOISE_MAX_TLP", ["greynoise", "max_tlp"], config
        )
        self.spoofable_confidence_level = get_config_variable(
            "GREYNOISE_SPOOFABLE_CONFIDENCE_LEVEL",
            ["greynoise", "spoofable_confidence_level"],
            config,
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
        self.api_url = "https://api.greynoise.io/v2/noise/"
        self.headers = {"key": self.greynoise_key, "Accept": "application/json"}
        self._CONNECTOR_RUN_INTERVAL_SEC = 60 * 60
        self.greynoise_id = None

    def _get_greynoise_id(self) -> int:
        """Get or create a Greynoise entity if not exists"""

        if self.greynoise_id is not None:
            return self.greynoise_id

        greynoise_entity = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=self.greynoise_ent_name
        )
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
            self.api_url + "context/" + observable["value"],
            headers=self.headers,
        )
        json_data = response.json()

        if response.status_code == 429:
            self.helper.log_info(
                f"Quota reached, waiting {self._CONNECTOR_RUN_INTERVAL_SEC} seconds."
            )
            sleep(self._CONNECTOR_RUN_INTERVAL_SEC)
            self._call_api(observable)
            return "Observable processed after quota reached, waiting 1 hour."
        if response.status_code >= 400:
            self.helper.log_error(
                f'HTTP error: {response.status_code} - error: {json_data["error"]}'
            )
            return json_data["error"]
        self.helper.log_info(
            f'Start processing observable {observable["observable_value"]}'
        )
        if "ip" in json_data:
            external_reference = self.helper.api.external_reference.create(
                source_name=self.greynoise_ent_name,
                url="https://viz.greynoise.io/ip/" + observable["observable_value"],
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
                self.spoofable_confidence_level
                if json_data["spoofable"]
                else self.helper.connect_confidence_level
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
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        if observable["entity_type"] == "IPv4-Addr":
            return self._call_api(observable)

    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    greyNoiseInstance = GreyNoiseConnector()
    greyNoiseInstance.start()
