import requests


class ConnectorAPI:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.url = config.tanium_url
        self.token = config.tanium_token
        self.ssl_verify = config.tanium_ssl_verify
        self.auto_ondemand_scan = config.tanium_auto_ondemand_scan
        self.computer_groups = config.tanium_computer_groups

        # Define headers in session and update when needed
        headers = {"session": self.token, "content-type": "application/json"}
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

    def get_alerts(self):
        """
        Get alerts from Tanium API.
        :return: Alerts data
        """
        alerts_url = self.url + "/plugin/products/threat-response/api/v1/alerts"
        response = self._request_data(alerts_url, params={"sort": "-createdAt"})
        body = response.json()
        return body["data"]

    def get_intel(self, intel_doc_id) -> dict:
        """
        Get alert related intelligence from Tanium API.
        :param intel_doc_id: Alert's intel doc ID
        :return: Intelligence data
        """
        intel_url = (
            self.url + "/plugin/products/threat-response/api/v1/intels/" + intel_doc_id
        )
        response = self._request_data(intel_url)
        body = response.json()
        return body["data"]
