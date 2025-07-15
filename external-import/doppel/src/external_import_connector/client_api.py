import requests
from tenacity import retry, stop_after_attempt, wait_fixed


class ConnectorClient:
    def __init__(self, helper, config):
        self.helper = helper
        self.config = config

        self.session = requests.Session()
        self.session.headers.update(
            {"x-api-key": self.config.api_key, "accept": "application/json"}
        )

    @retry(wait=wait_fixed(5), stop=stop_after_attempt(3))  # Default fallback values
    def _request_data(self, api_url, params=None):
        try:
            response = self.session.get(api_url, params=params)
            self.helper.connector_logger.info("[API] Requesting data", {"url": api_url})
            response.raise_for_status()
            return response
        except requests.HTTPError as http_err:
            error_msg = ""
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

    def get_alerts(self, last_activity_timestamp, page=0):
        url = f"{self.config.api_base_url}{self.config.alerts_endpoint}"
        params = {"last_activity_timestamp": last_activity_timestamp, "page": page}

        # Dynamically set retry settings
        self._request_data.retry.wait = wait_fixed(self.config.retry_delay)
        self._request_data.retry.stop = stop_after_attempt(self.config.max_retries)

        return self._request_data(url, params=params)
