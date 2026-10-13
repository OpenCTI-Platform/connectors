import requests
from pycti import OpenCTIConnectorHelper
from ransomwarelive_client.exceptions import RansomwareAPIError
from ransomwarelive_client.protocol import (
    MAX_RETRIES,
    REQUEST_TIMEOUT_SECONDS,
    RETRY_BACKOFF_FACTOR,
    RETRY_BACKOFF_JITTER,
)
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RansomwareAPIV2Client:
    def __init__(self, helper: OpenCTIConnectorHelper, base_url: str):
        self.helper = helper
        self.base_url = base_url.rstrip("/")
        self._session = self._build_session()

    @staticmethod
    def _build_session() -> requests.Session:
        retry = Retry(
            total=MAX_RETRIES,
            status_forcelist=[429],
            backoff_factor=RETRY_BACKOFF_FACTOR,
            backoff_jitter=RETRY_BACKOFF_JITTER,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _send_request(self, url: str):
        try:
            response = self._session.get(
                url,
                headers={"accept": "application/json", "User-Agent": "OpenCTI"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            if response.content:
                return response.json()
            return None

        except requests.exceptions.RetryError as err:
            self.helper.connector_logger.error(
                "Exceeded maximum retries for Ransomware API due to rate limiting",
                {"url": f"GET {url}", "status_code": 429, "retries": MAX_RETRIES},
            )
            raise RansomwareAPIError(
                f"Error while fetching Ransomware API: HTTP 429 after {MAX_RETRIES} retries",
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

    def _get_feed(self, path: str) -> list[dict]:
        url = f"{self.base_url}/{path.lstrip('/')}"
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

    def get_groups(self) -> list[dict]:
        return self._get_feed("groups")

    def get_recent_victims(self) -> list[dict]:
        return self._get_feed("recentvictims")

    def get_victims(self, year: int, month: int) -> list[dict]:
        return self._get_feed(f"victims/{year}/{month}")
