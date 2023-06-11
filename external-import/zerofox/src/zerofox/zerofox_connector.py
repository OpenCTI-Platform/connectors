import os

import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .zerofox_fetchers import fetch_data_from_zerofox_endpoint


class ZeroFoxConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        print("Initializing ZeroFox connector...")
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        # ZeroFOX API credentials
        self.zerofox_username = get_config_variable(
            "ZEROFOX_USERNAME",
            ["zerofox", "username"],
            config,
        )
        self.zerofox_password = get_config_variable(
            "ZEROFOX_PASSWORD",
            ["zerofox", "password"],
            config,
        )

    def get_access_token(self):
        # Prepare the payload
        payload = {"username": self.zerofox_username, "password": self.zerofox_password}

        # Specify the headers
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        # Send the POST request
        response = requests.post(
            "https://api.zerofox.com/auth/token/", json=payload, headers=headers
        )

        # Check if the request was successful
        if response.status_code == 200:
            response_json = response.json()
            access_token = response_json.get("access", None)

            if not access_token:
                raise Exception("Access token not found in response")

            return access_token
        else:
            raise Exception(
                f"Request failed with status code {response.status_code}, response: {response.text}"
            )

    def run(self, endpoint):
        access_token = self.get_access_token()
        fetch_data_from_zerofox_endpoint(access_token, endpoint, self.helper)
