import urllib

import requests


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        headers = {
            "Content": "application/json",
        }

        if hasattr(self.config, "api_key") and self.config.api_key:
            headers["key"] = self.config.api_key

        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            params = urllib.parse.urlencode(params)
            if not params:
                self.helper.connector_logger.error("[API] Error During parse urlib")
                return None

            response = self.session.get(api_url, auth=None, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            if response.ok:
                return response
            return None

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_entities(self, params=None) -> list | None:
        """
        If params is None, retrieve all IPs in the Github Repository
        :param params: Optional Params to filter what list to return
        :return: A list of IPs
        """
        ips = []
        try:
            response = self._request_data(self.config.api_url, params=params)
            if response is not None:
                data_json = response.json()
                for d in data_json["data"]:
                    value = str(d["ipAddress"])
                    country_code = str(d["countryCode"])
                    confidence_score = str(d["abuseConfidenceScore"])
                    last_reported = str(d["lastReportedAt"])
                    ips.append(
                        {
                            "value": value,
                            "country_code": country_code,
                            "confidence_score": confidence_score,
                            "last_reported": last_reported,
                        }
                    )
            return ips
        except Exception as err:
            self.helper.connector_logger.error(err)
            return None
