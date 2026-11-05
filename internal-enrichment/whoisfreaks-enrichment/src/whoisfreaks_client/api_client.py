"""HTTP client for the WhoisFreaks Live WHOIS API."""

import re

import requests
from connectors_sdk.exceptions.error import DataRetrievalError
from requests.adapters import HTTPAdapter, Retry
from whoisfreaks_client.models import WhoisRecord

_API_KEY_IN_URL = re.compile(r"(apiKey=)[^&\s'\"]+")


class WhoisFreaksAPIError(DataRetrievalError):
    """The WhoisFreaks API refused or failed a request."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"WhoisFreaks API error {status_code}: {message}")


class WhoisFreaksClient:
    """Look up a domain's live WHOIS with one `/v2.0/whois/live` request.

    The API key is passed as the `apiKey` query parameter. It is removed from
    any error text so it never reaches logs or the OpenCTI work panel.
    """

    _WHOIS_PATH = "/v2.0/whois/live"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.whoisfreaks.com",
        timeout: int = 30,
    ):
        self._api_key = api_key
        self._url = base_url.rstrip("/") + self._WHOIS_PATH
        self._timeout = timeout

        # Retry transient server errors only: a 429 means the plan's quota is used up,
        # and `respect_retry_after_header=False` keeps a 429 Retry-After header from
        # making the client sleep past the configured timeout.
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=(502, 503, 504),
            allowed_methods=("GET",),
            raise_on_status=False,
            respect_retry_after_header=False,
        )
        self._session = requests.Session()
        self._session.mount("https://", HTTPAdapter(max_retries=retry))
        self._session.mount("http://", HTTPAdapter(max_retries=retry))
        self._session.headers.update({"Accept": "application/json"})

    def lookup(self, domain: str) -> WhoisRecord:
        """Return the live WHOIS record for `domain`."""
        response = self._get(domain)
        if response.status_code != 200:
            raise WhoisFreaksAPIError(response.status_code, _error_message(response))
        try:
            payload = response.json()
        except ValueError as err:
            raise WhoisFreaksAPIError(200, "the response is not JSON") from err

        # The API reports application-level failures with `status: false`.
        if payload.get("status") is False:
            raise WhoisFreaksAPIError(200, _error_message(response))

        return WhoisRecord.from_response(payload)

    def _get(self, domain: str) -> requests.Response:
        params = {
            "apiKey": self._api_key,
            "whois": "live",
            "domainName": domain,
            "format": "json",
        }
        try:
            return self._session.get(self._url, params=params, timeout=self._timeout)
        except requests.RequestException as err:
            # The original exception text embeds the request URL with the API key;
            # drop it from the chain (`from None`) and keep only the redacted message,
            # so the key never reaches a formatted traceback.
            message = _API_KEY_IN_URL.sub(r"\1***", str(err))
            raise DataRetrievalError(
                f"Could not reach the WhoisFreaks API: {message}"
            ) from None


def _error_message(response: requests.Response) -> str:
    """Extract the human-readable error from a WhoisFreaks response."""
    try:
        body = response.json()
    except ValueError:
        return response.reason or "unknown error"
    if isinstance(body, dict):
        return (
            body.get("error")
            or body.get("message")
            or body.get("whois_error")
            or response.reason
            or "unknown error"
        )
    return response.reason or "unknown error"
