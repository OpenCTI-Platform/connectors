import requests
import urllib.parse

from models.harfanglab import (
    Alert as HarfanglabAlert,
    Indicator as HarfanglabIndicator,
    Threat as HarfanglabThreat,
)


class HarfanglabClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.api_base_url = self.config.harfanglab_api_base_url
        self.ssl_verify = self.config.harfanglab_ssl_verify

        # Define headers in session and update when needed
        headers = {
            "Authorization": "Token " + self.config.harfanglab_token,
            "Accept": "application/json",
        }
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request(self, **kwargs):
        """
        Internal method to handle API requests.
        :param kwargs: Any arguments accepted by request.request()
        :return: Parsed response body
        """
        method = kwargs.get("method", "get")
        url = kwargs.get("url")

        try:
            response = self.session.request(method, **kwargs)
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP {method.upper()} Request to endpoint", {"url_path": url}
            )

            return response.json()
        except requests.RequestException as err:
            error_msg = f"[API] Error while sending {method.upper()} request: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {url}, "error": {str(err)}}
            )
            return None

    def generate_alerts_lists(self, threat_id=None):
        """
        Get lists of alerts from Harfanglab API.
        :return: Generator yielding list of alerts from Harfanglab
        """
        alerts_status = self.config.harfanglab_import_security_events_filters_by_status
        alerts_types = self.config.harfanglab_import_filters_by_alert_type

        path = "/api/data/alert/alert/Alert"
        params = {
            "maturity": "stable",
            "status": alerts_status,
            "alert_type": alerts_types,
            "threat_key": threat_id,  # filter alerts for given threat
            "ordering": "+alert_time",
            "limit": 100,
        }
        url = f"{self.api_base_url}{path}?{urllib.parse.urlencode(params)}"

        while url:
            data = self._request(
                method="get",
                url=url,
                params=params,
                verify=self.ssl_verify,
            )
            results = data["results"] if data else []

            yield [HarfanglabAlert(result) for result in results]
            url = (
                f"{self.api_base_url}{data['next']}" if data else None
            )  # next page url or None

    def generate_threats_lists(self):
        """
        Get lists of threats from Harfanglab API.
        :return: Generator yielding list of threats from Harfanglab
        """
        path = "/api/data/alert/alert/Threat"
        params = {
            "limit": 100,
            "ordering": "+creation_date",
        }
        url = f"{self.api_base_url}{path}?{urllib.parse.urlencode(params)}"

        while url:
            data = self._request(
                method="get",
                url=url,
                params=params,
                verify=self.ssl_verify,
            )
            results = data["results"] if data else []

            yield [HarfanglabThreat(result) for result in results]
            url = (
                f"{self.api_base_url}{data['next']}" if data else None
            )  # next page url or None

    def get_alert_ioc_rules(self, rule_name: str) -> list[HarfanglabIndicator]:
        """
        Get a list of IOCs (indicators) for a given rule name.
        :param rule_name: IOC rule name
        :return: List of indicators from Harfanglab
        """
        path = "/api/data/threat_intelligence/IOCRule"
        params = {"search": rule_name}

        data = self._request(
            method="get",
            url=self.api_base_url + path,
            params=params,
            verify=self.ssl_verify,
        )
        results = data["results"] if data else []

        return [HarfanglabIndicator(result) for result in results]

    def get_alert_sigma_rules(self, rule_name) -> list[HarfanglabIndicator]:
        """
        Get a list of Sigma indicators for a given rule name.
        :param rule_name: Sigma rule name
        :return: List of indicators from Harfanglab
        """
        path = "/api/data/threat_intelligence/SigmaRule"
        params = {"search": rule_name}

        data = self._request(
            method="get",
            url=self.api_base_url + path,
            params=params,
            verify=self.ssl_verify,
        )
        results = data["results"] if data else []

        return [HarfanglabIndicator(result) for result in results]

    def get_alert_yara_files(self, rule_name) -> list[HarfanglabIndicator]:
        """
        Get a list of YARA indicators for a given rule name.
        :param rule_name: YARA rule name
        :return: List of indicators from Harfanglab
        """
        path = "/api/data/threat_intelligence/YaraFile"
        params = {"search": rule_name}

        data = self._request(
            method="get",
            url=self.api_base_url + path,
            params=params,
            verify=self.ssl_verify,
        )
        results = data["results"] if data else []

        return [HarfanglabIndicator(result) for result in results]
