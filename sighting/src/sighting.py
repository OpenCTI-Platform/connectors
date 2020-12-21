import yaml
import os
import requests
import json
import pycountry

from stix2 import Relationship, Location, Bundle
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils, get_config_variable


class SightingConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        print(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    sightingInstance = SightingConnector()
    sightingInstance.start()
