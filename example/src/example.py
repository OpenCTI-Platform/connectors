import yaml
import os

from IPy import IP
from pycti import OpenCTIConnectorHelper, get_config_variable


class ExampleConnector:
    """ This is the main class for our Example connector """

    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # Load our example variable either from the config.yml
        # or the docker compose variable (environment).
        self.variable = get_config_variable(
            "EXAMPLE_VARIABLE", ["example", "variable"], config
        )

        self.tag_private_IP = self.helper.api.tag.create(
            tag_type="Example", value="IP:RFC1918", color="#800080",
        )

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_observable.read(id=entity_id)

        # Extract IP from entity data
        observable_value = observable["observable_value"]

        # Use the IPy function iptype() to determine if the IP address is from a
        # private IP address range (RFC1918).
        ip_type = IP(observable_value).iptype()

        if ip_type == "PRIVATE":
            # We add a tag to the observable so people know to be conscious
            self.helper.api.stix_entity.add_tag(
                id=observable["id"], tag_id=self.tag_private_IP["id"]
            )

        return [f"IP address {observable_value} is of type {ip_type}"]

    # Start the main loop and process all the messages
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    ExampleInstance = ExampleConnector()
    ExampleInstance.start()
