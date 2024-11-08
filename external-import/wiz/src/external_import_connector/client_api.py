import requests

WIZ_STIX_URL = "https://www.wiz.io/api/feed/cloud-threat-landscape/stix.json"


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {"User-Agent": "opencti-importer"}
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
        """
        If params is None, retrieve all bundles
        :param params: Optional Params to pass to requests
        :return: A list of stix objects from Wiz threats
        TOOD: Add filter
        """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================

            response = self._request_data(WIZ_STIX_URL, params=params)

            return response.json()
            # ===========================
            # === Add your code above ===
            # ===========================

        except Exception as err:
            self.helper.connector_logger.error(err)
