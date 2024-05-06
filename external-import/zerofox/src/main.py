import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from zerofox.app import ZeroFox
from zerofox.app.endpoints import CTIEndpoint
from zerofox.zerofox_fetchers import fetch_data_from_zerofox_endpoint

if __name__ == "__main__":
    try:
        # Instantiate the ZeroFoxConnector
        config_file_path = os.path.dirname(
            os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        # ZeroFOX API credentials
        username = get_config_variable(
            "ZEROFOX_USERNAME",
            ["zerofox", "username"],
            config,
        )
        password = get_config_variable(
            "ZEROFOX_PASSWORD",
            ["zerofox", "password"],
            config,
        )
        print(f"ZeroFOX username: {username}, password: {password}")
        connector = ZeroFox(user=username, token=password)
        print("ZeroFOX connector initialized successfully")

        # Fetch data from ZeroFOX endpoint
        endpoints = [CTIEndpoint.Botnet,
                     CTIEndpoint.Malware, CTIEndpoint.Ransomware]
        for endpoint in endpoints:
            print(f"Fetching data from endpoint: {endpoint.value}")
            fetch_data_from_zerofox_endpoint(
                connector, endpoint, OpenCTIConnectorHelper(config))
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
