import urllib.parse
from datetime import datetime

import requests

from .models import harfanglab


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
        method = kwargs.get("method")
        url = kwargs.get("url")

        try:
            response = self.session.request(verify=self.ssl_verify, **kwargs)
            response.raise_for_status()

            self.helper.connector_logger.info(
                f"[API] HTTP {method.upper()} Request to endpoint", {"url": url}
            )

            return response.json() if response.content else None
        except requests.RequestException as err:
            error_msg = f"[API] Error while sending {method.upper()} request: "
            self.helper.connector_logger.error(
                error_msg, {"url": {url}, "error": {str(err)}}
            )
            return None

    def generate_alerts(
        self, since: datetime | None = None, threat_id: str | None = None
    ):
        """
        Get lists of alerts from Harfanglab API.
        :param since: Minimum alerts creation datetime
        :param threat_id: ID of the threat to filter alerts for
        :return: Generator yielding list of alerts from Harfanglab
        """
        path = "/api/data/alert/alert/Alert"
        params = {
            "status": self.config.harfanglab_alert_statuses,
            "alert_type": self.config.harfanglab_alert_types,
            "maturity": "stable",
            "ordering": "alert_time",  # alert_time ASC
            "limit": 100,
        }
        if since:
            params["from"] = since.isoformat()
        if threat_id:
            params["threat_key"] = threat_id  # filter alerts for given threat

        # params are encoded directly in url, instead of sent as self._request() argument,
        # to avoid sending them twice (they are already encoded in next_path)
        url = f"{self.api_base_url}{path}?{urllib.parse.urlencode(params)}"

        while url:
            data = self._request(
                method="get",
                url=url,
            )

            results = data["results"] if data else []
            alerts = [harfanglab.Alert(result) for result in results]
            for alert in alerts:
                yield alert

            next_path = data["next"] if data else None
            if next_path:
                url = f"{self.api_base_url}{next_path}"
            else:
                url = None

    def generate_threats(self, since: datetime | None = None):
        """
        Get lists of threats from Harfanglab API.
        :param since: Minimum threats creation datetime
        :return: Generator yielding list of threats from Harfanglab
        """
        path = "/api/data/alert/alert/Threat"
        params = {
            "limit": 100,
            "ordering": "creation_date",  # creation_date ASC
        }
        if since:
            params["from"] = since.isoformat()

        # params are encoded directly in url, instead of sent as self._request() argument,
        # to avoid sending them twice (they are already encoded in next_path)
        url = f"{self.api_base_url}{path}?{urllib.parse.urlencode(params)}"

        while url:
            data = self._request(
                method="get",
                url=url,
            )

            results = data["results"] if data else []
            threats = [harfanglab.Threat(result) for result in results]
            for threat in threats:
                yield threat

            next_path = data["next"] if data else None
            if next_path:
                url = f"{self.api_base_url}{next_path}"
            else:
                url = None

    def get_alert_ioc_rule(self, alert: harfanglab.Alert) -> harfanglab.IocRule | None:
        """
        Get an IOC rule for a given alert.
        :param alert: Alerts to get IOC for
        :return: IOC rule from Harfanglab
        """
        ioc_value = None
        if alert.message:
            split_message = alert.message.split("=") or alert.message.split(":")
            if len(split_message) == 2:
                ioc_value = split_message[1]
        if ioc_value is None:
            return None

        path = "/api/data/threat_intelligence/IOCRule"
        params = {"value__exact": ioc_value}
        url = f"{self.api_base_url}{path}"

        data = self._request(
            method="get",
            url=url,
            params=params,
        )
        if data and len(data["results"]):
            result = data["results"][0]
            return harfanglab.IocRule(result)

    def get_alert_sigma_rule(
        self, alert: harfanglab.Alert
    ) -> harfanglab.SigmaRule | None:
        """
        Get a Sigma rule for a given alert.
        :param alert: Alerts to get Sigma rule for
        :return: Sigma rule from Harfanglab
        """
        if alert.rule_name is None:
            return None

        path = "/api/data/threat_intelligence/SigmaRule"
        params = {"rule_name__exact": alert.rule_name}
        url = f"{self.api_base_url}{path}"

        data = self._request(
            method="get",
            url=url,
            params=params,
        )
        if data and len(data["results"]):
            result = data["results"][0]
            return harfanglab.SigmaRule(result)

    def get_alert_yara_signature(
        self, alert: harfanglab.Alert
    ) -> harfanglab.YaraSignature | None:
        """
        Get a YARA signature for a given alert.
        :param alert: Alerts to get YARA signature for
        :return: Yara signature from Harfanglab
        """
        yara_file_name = None
        if alert.rule_name:
            split_rule_name = alert.rule_name.split(":")
            if len(split_rule_name) == 2:
                yara_file_name = split_rule_name[1].strip()
        if yara_file_name is None:
            return None

        path = "/api/data/threat_intelligence/YaraFile"
        params = {"name__exact": yara_file_name}
        url = f"{self.api_base_url}{path}"

        data = self._request(
            method="get",
            url=url,
            params=params,
        )
        if data and len(data["results"]):
            result = data["results"][0]
            return harfanglab.YaraSignature(result)

    def get_threat_note(self, threat_id=None) -> harfanglab.ThreatNote:
        path = f"/api/data/alert/alert/Threat/{threat_id}/note"
        url = f"{self.api_base_url}{path}"

        data = self._request(
            method="get",
            url=url,
        )
        if data:
            return harfanglab.ThreatNote(data)
