import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {"Bearer": self.config.api_key}
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
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================

            # response = self._request_data(self.config.api_base_url, params=params)

            # return response.json()
            # ===========================
            # === Add your code above ===
            # ===========================

            raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)
