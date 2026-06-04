import requests
from pycti import OpenCTIConnectorHelper
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RansomwareAPIError(Exception):
    """Custom wrapper for exceptions raised in RansomwareAPIClient"""


_MAX_RETRIES = 5
_RETRY_BACKOFF_FACTOR = 60  # seconds — matches the API's "1 per 1 minute" rate limit
_RETRY_BACKOFF_JITTER = (
    30  # seconds of random jitter to spread retries across instances
)
_REQUEST_TIMEOUT_SECONDS = 30

API_BASE_URL = "https://api.ransomware.live/v2/"


class RansomwareAPIClient:
    def __init__(self, helper: OpenCTIConnectorHelper):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self._session = self._build_session()

    @staticmethod
    def _build_session() -> requests.Session:
        retry = Retry(
            total=_MAX_RETRIES,
            status_forcelist=[429],
            backoff_factor=_RETRY_BACKOFF_FACTOR,
            backoff_jitter=_RETRY_BACKOFF_JITTER,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _send_request(self, url: str):
        """
        Send a request to Ransomware API.
        Retries up to _MAX_RETRIES times on HTTP 429 with exponential backoff and jitter.
        :param url: request URL in string
        :return: response data returned by the API
        """
        try:
            response = self._session.get(
                url,
                headers={"accept": "application/json", "User-Agent": "OpenCTI"},
                timeout=_REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            if response.content:
                return response.json()
            return None

        except requests.exceptions.RetryError as err:
            self.helper.connector_logger.error(
                "Exceeded maximum retries for Ransomware API due to rate limiting",
                {"url": f"GET {url}", "status_code": 429, "retries": _MAX_RETRIES},
            )
            raise RansomwareAPIError(
                f"Error while fetching Ransomware API: HTTP 429 after {_MAX_RETRIES} retries",
                {"url": f"GET {url}", "status_code": 429},
            ) from err

        except requests.exceptions.HTTPError as err:
            status = err.response.status_code
            text = err.response.text or ""

            if status == 500 and "No victims found" in text:
                return []

            self.helper.connector_logger.error(
                "HTTP error while fetching Ransomware API",
                {"url": f"GET {url}", "status_code": status, "response_body": text},
            )
            raise RansomwareAPIError(
                f"Error while fetching Ransomware API: HTTP {status}",
                {"url": f"GET {url}", "status_code": status, "response_body": text},
            ) from err

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "Request error while fetching Ransomware API",
                {"url": f"GET {url}", "error": str(err)},
            )
            raise RansomwareAPIError(
                f"Error while fetching Ransomware API: {err}",
                {"url": f"GET {url}", "error": err},
            ) from err

    def get_feed(self, path: str) -> list[dict]:
        """
        Get feed for given path.
        :param path: path to get feed from.
        :return: data's feed items
        """
        url = f"{API_BASE_URL}{path}"
        data = self._send_request(url)

        if data is None:
            return []

        if not isinstance(data, list):
            raise RansomwareAPIError(
                "Unexpected Ransomware API response type for feed",
                {"url": f"GET {url}", "response_type": type(data).__name__},
            )
        if not all(isinstance(item, dict) for item in data):
            raise RansomwareAPIError(
                "Unexpected Ransomware API feed item type",
                {"url": f"GET {url}", "response_type": "list"},
            )

        return data
