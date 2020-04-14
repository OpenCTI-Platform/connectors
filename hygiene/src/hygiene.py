import os
import yaml

from pymispwarninglists import WarningLists
from pycti import OpenCTIConnectorHelper


class HygieneConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.warninglists = WarningLists()

    def _process_observable(self, observable):
        # Extract IPv4, IPv6 and Domain from entity data
        observable_value = observable["observable_value"]

        # Search in warninglist
        result = self.warninglists.search(observable_value)

        # Iterate over the hits
        if result:
            self.helper.log_info(
                "Hit found for %s in warninglists" % (observable_value)
            )

            for hit in result:
                self.helper.log_info(
                    " %s %s %s %s" % (hit.type, hit.name, hit.version, hit.description)
                )
                # Create Hygiene Tag
                tag_hygiene = self.helper.api.tag.create(
                    tag_type="Hygiene", value="Hygiene:" + hit.name, color="#fc0341",
                )

                self.helper.api.stix_entity.add_tag(
                    id=observable, tag_id=tag_hygiene["id"]
                )
            return ["observable value found on warninglist and tagged accordingly"]

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_observable.read(id=entity_id)

        # Check for supported types
        observable_type = observable["entity_type"]
        supported_types = [
            "ipv4-addr",
            "ipv6-addr",
            "domain",
            "file-md5",
            "file-sha1",
            "file-sha256",
        ]

        if any(word in observable_type for word in supported_types):
            return self._process_observable(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    HygieneInstance = HygieneConnector()
    HygieneInstance.start()
