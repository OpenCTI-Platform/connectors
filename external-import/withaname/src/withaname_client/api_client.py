import requests
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


class WithanameClient:
    """
    API client for querying the DDoSIA targets and configurations from witha.name.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, base_url: HttpUrl):
        """
        Initialize the DDoSIA API client.

        Args:
            helper: OpenCTI connector helper for structured logging.
            base_url: The base URL of the witha.name API.
        """
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")

        # Set up requests Session with connection pool retries
        self.session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False,
        )
        self.session.mount("http://", HTTPAdapter(max_retries=retries))
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def _request_json(self, path: str, params: dict = None) -> dict:
        """
        Internal helper to perform GET requests and handle exceptions.

        Args:
            path: Relative API path (e.g., "/api/configs").
            params: Optional query parameters.

        Returns:
            The parsed JSON response as a dictionary.

        Raises:
            requests.RequestException: If the request fails or returns an error status.
        """
        url = f"{self.base_url}{path}"
        self.helper.connector_logger.debug(
            "[API] Fetching data", {"url": url, "params": params}
        )

        try:
            # 30 seconds timeout for connect and read
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()

        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[API] HTTP request failed",
                {"url": url, "error": str(err)},
            )
            raise

    def get_configs(self, page: int = 1) -> dict:
        """
        Retrieve the list of available DDoSIA target configurations.

        Args:
            page: The page number to retrieve. Defaults to 1.

        Returns:
            A dictionary containing the paginated list of configurations (items, total, etc.).
        """
        return self._request_json("/api/configs", params={"page": page})

    def get_config(self, cfg_id: str) -> dict:
        """
        Retrieve the detailed DDoSIA target configuration for a given configuration ID.

        Args:
            cfg_id: The ID of the configuration to fetch.

        Returns:
            A dictionary containing the detailed target list.
        """
        return self._request_json(f"/api/config/{cfg_id}")
