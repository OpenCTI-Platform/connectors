import sys
import time

from zerofox.zerofox_connector import ZeroFoxConnector
from zerofox.zerofox_fetchers import fetch_data_from_zerofox_endpoint

if __name__ == "__main__":
    try:
        # Instantiate the ZeroFoxConnector
        connector = ZeroFoxConnector()

        # Fetch data from ZeroFOX endpoint
        access_token = connector.get_access_token()
        endpoints = ["botnet", "malware", "ransomware"]
        for endpoint in endpoints:
            connector.run(endpoint)
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
