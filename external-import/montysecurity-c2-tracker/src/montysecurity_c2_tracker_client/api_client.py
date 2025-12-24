import requests
import re
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class MontysecurityC2TrackerClient:
    def __init__(self, helper: OpenCTIConnectorHelper):
        """
        Initialize the client with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `api_key`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            base_url (str): The external API base URL.
            api_key (str): The API key to authenticate the connector to the external API.
        """
        self.helper = helper

        # Define headers in session and update when needed
        headers = {}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_entities(self, params=None) -> dict:
        try:
            # ===========================
            # === Add your code below ===
            # ===========================
            self.helper.connector_logger.info("Get Malware Entities")

            malwareListUrl = "https://github.com/montysecurity/C2-Tracker/tree/main/data"
            response = self._request_data(malwareListUrl, params=params)
            self.helper.connector_logger.info("Status code from github.com: ", response.status_code)
            malwareList = list(set(re.findall("\"[\w|\s|\d|\.]+IPs\.txt\"", response.text)))

            return malwareList

            # self.helper.connector_logger.info("Get Malware IPs")
            #
            # malwareIPsBaseUrl = "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/"
            # malwareIPs = set()
            # i = 0
            # for malware in malwareList:
            #     malwareList[i] = str(malware).strip('"')
            #     i += 1
            # for malware in malwareList:
            #     print(f"[+] Looking at {malware}")
            #     url = str(malwareIPsBaseUrl + str(malware).replace(" ", "%20"))
            #     request = requests.get(url)
            #     ips = str(request.text).split("\n")
            #     ips.pop()
            #     for ip in ips:
            #         malwareIPs.add(ip)
            # self.helper.connector_logger.info(malwareIPs)



            # return response.json()
            # ===========================
            # === Add your code above ===
            # ===========================

            # raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)