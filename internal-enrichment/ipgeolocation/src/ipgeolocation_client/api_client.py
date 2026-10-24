"""HTTP client for the IPGeolocation.io v3 IP Location API."""

import re

import requests
from connectors_sdk.exceptions.error import DataRetrievalError
from ipgeolocation_client.models import IPIntelligence
from requests.adapters import HTTPAdapter, Retry

_API_KEY_IN_URL = re.compile(r"(apiKey=)[^&\s'\"]+")


class IPGeolocationAPIError(DataRetrievalError):
    """The IPGeolocation.io API refused or failed a request."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"IPGeolocation.io API error {status_code}: {message}")


class IPGeolocationClient:
    """Look up IP addresses with one `/v3/ipgeo` request each.

    The optional modules (`security`, `abuse`, `hostname`) are requested with `include`.
    Free plans refuse them with HTTP 401; the client then falls back to the base lookup
    (location, ASN) and stops asking for them.
    """

    _IPGEO_PATH = "/v3/ipgeo"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.ipgeolocation.io",
        timeout: int = 30,
        include: tuple[str, ...] = ("security", "abuse", "hostname"),
    ):
        self._api_key = api_key
        self._url = base_url.rstrip("/") + self._IPGEO_PATH
        self._timeout = timeout
        self._include = ",".join(include)

        # Retry transient server errors only: a 429 means the plan's quota is used up.
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=(502, 503, 504),
            allowed_methods=("GET",),
            raise_on_status=False,
        )
        self._session = requests.Session()
        self._session.mount("https://", HTTPAdapter(max_retries=retry))
        self._session.mount("http://", HTTPAdapter(max_retries=retry))
        self._session.headers.update({"Accept": "application/json"})

    def lookup(self, ip: str) -> IPIntelligence:
        """Return everything the plan allows about `ip`."""
        response = self._get(ip, self._include)
        if response.status_code == 401 and self._include:
            # Free plans refuse the optional modules: keep the base lookup they allow.
            base = self._get(ip, "")
            if base.status_code == 200:
                self._include = ""
            response = base
        if response.status_code != 200:
            raise IPGeolocationAPIError(response.status_code, _error_message(response))
        try:
            return IPIntelligence.from_ipgeo_response(response.json())
        except ValueError as err:
            raise IPGeolocationAPIError(200, "the response is not JSON") from err

    def _get(self, ip: str, include: str) -> requests.Response:
        params = {"apiKey": self._api_key, "ip": ip}
        if include:
            params["include"] = include
        try:
            return self._session.get(self._url, params=params, timeout=self._timeout)
        except requests.RequestException as err:
            message = _API_KEY_IN_URL.sub(r"\1***", str(err))
            raise DataRetrievalError(
                f"Could not reach the IPGeolocation.io API: {message}"
            ) from err


def _error_message(response: requests.Response) -> str:
    try:
        return response.json().get("message") or response.reason
    except ValueError:
        return response.reason or "unknown error"
