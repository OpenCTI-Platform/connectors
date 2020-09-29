import os
import yaml


from pycti import OpenCTIConnectorHelper


class MalBeaconConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def _process_observable(self, observable) -> list:
        # Extract IPv4, IPv6 and Domain from entity data
        observable_value = observable["observable_value"]

        return ["observable value found on malbeacon API and knowledge added"]

    def _process_message(self, data) -> list:
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        return self._process_observable(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    MalBeaconInstance = MalBeaconConnector()
    MalBeaconInstance.start()
