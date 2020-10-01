import os
from requests import api
import yaml
import logging
import requests

from urllib.parse import urljoin

from pycti import OpenCTIConnectorHelper, get_config_variable

logger = logging.getLogger(__name__)


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
        self.api_key = get_config_variable(
            "MALBEACON_API_KEY", ["malbeacon", "api_key"], config
        )

    def _process_observable(self, observable) -> list:
        # Extract IPv4, IPv6, Hostname and Domain from entity data
        observable_value = observable["observable_value"]

        print(observable)

        return ["observable value found on malbeacon API and knowledge added"]

    def _process_message(self, data) -> list:
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        return self._process_observable(observable)

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)

    def _api_call(self, url_path):
        api_base_url = "https://api.malbeacon.com/v1/"
        url = urljoin(api_base_url, url_path)
        try:
            r = requests.get(url, headers={"X-Api-Key": self.api_key})
            data = r.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"error in malbeacon api request: {e}")
            return None
        return data

    def _process_ipv4(self, ip_address):
        pass

    def _process_fqdn(self, fqdn):
        pass


if __name__ == "__main__":
    MalBeaconInstance = MalBeaconConnector()
    MalBeaconInstance.start()
