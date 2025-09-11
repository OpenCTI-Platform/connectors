import requests
from tenacity import retry, stop_after_attempt, wait_fixed


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        self.session = requests.Session()
        headers = {"x-api-key": self.config.api_key, "accept": "application/json"}
        # Add user_api_key if provided
        if hasattr(self.config, "user_api_key") and self.config.user_api_key:
            headers["x-user-api-key"] = self.config.user_api_key

        self.session.headers.update(headers)

    @retry(wait=wait_fixed(5), stop=stop_after_attempt(3))  # Default fallback values
    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: response
        """
        try:
            response = self.session.get(api_url, params=params)
            self.helper.connector_logger.info("[API] Requesting data", {"url": api_url})
            response.raise_for_status()
            return response
        except requests.HTTPError as http_err:
            try:
                error_json = http_err.response.json()
                error_msg = error_json.get("message", http_err.response.text)
            except Exception:
                error_msg = http_err.response.text or str(http_err)

            self.helper.connector_logger.error(
                "[API] HTTP error during fetch",
                {
                    "url": api_url,
                    "status_code": http_err.response.status_code,
                    "error": error_msg,
                },
            )
            raise
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] Request error during fetch",
                {
                    "url": api_url,
                    "error": str(err),
                },
            )
            raise

    def get_alerts(self, last_activity_timestamp: str, page: int = 0):
        """
        Retrieve alerts from api
        """
        url = f"{self.config.api_base_url}{self.config.alerts_endpoint}"

        if last_activity_timestamp.endswith("+00:00"):
            last_activity_timestamp = last_activity_timestamp.replace("+00:00", "")

        # Dynamically set retry settings
        self._request_data.retry.wait = wait_fixed(self.config.retry_delay)
        self._request_data.retry.stop = stop_after_attempt(self.config.max_retries)

        res = []
        while True:
            params = {"last_activity_timestamp": last_activity_timestamp, "page": page}
            response = self._request_data(url, params=params)
            self.helper.connector_logger.info(
                "[DoppelConnector] Fetching alerts", params
            )
            if not (alerts := response.json().get("alerts")):
                break
            self.helper.connector_logger.info("Fetched alerts", {"count": len(alerts)})
            res.extend(alerts)
            page += 1
        return res
