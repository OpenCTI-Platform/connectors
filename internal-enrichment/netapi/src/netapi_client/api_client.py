"""HTTP client for the NetAPI JSON API (https://netapi.com/help/api/#json-api)."""

from typing import Any

import requests
from connectors_sdk.exceptions.error import DataRetrievalError
from requests.adapters import HTTPAdapter, Retry

USER_AGENT = (
    "opencti-connector-netapi (+https://github.com/OpenCTI-Platform/connectors)"
)


class NetAPIError(DataRetrievalError):
    """The NetAPI JSON API refused or failed a request."""

    def __init__(self, status_code: int, code: str, message: str):
        self.status_code = status_code
        self.code = code
        self.message = message
        super().__init__(f"NetAPI error {status_code} ({code}): {message}")


class NetAPIClient:
    """Call the free NetAPI JSON API methods, one GET request each.

    Every method answers JSON; an error is `{"error": {"code": ..., "message": ...}}`
    with an HTTP status of 400 or more. A token is optional and only raises the
    request limits (30 a minute and 1,000 a day per IP address without one).
    """

    def __init__(
        self,
        base_url: str = "https://netapi.com/api-json/",
        api_token: str | None = None,
        timeout: int = 30,
    ):
        self._url = base_url
        self._timeout = timeout

        # Retry transient server errors only: a 429 means the limit of the
        # minute or the day is used up and is reported to the work.
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
        self._session.headers.update(
            {"Accept": "application/json", "User-Agent": USER_AGENT}
        )
        if api_token:
            self._session.headers["Authorization"] = f"Bearer {api_token}"

    def compromised_check(self, value: str) -> dict[str, Any]:
        """Whether `value` (a domain, hostname or IPv4 address) is in the compromised feed.

        A hostname is also matched through its registered domain; the answer says
        which entry matched (`matched_value`), when it was first and last seen, the
        public feed that reported it and the registrar of a domain.
        """
        return self._get("compromised-check", value=value)

    def domain_rank(self, domain: str) -> dict[str, Any]:
        """The position of `domain` in the NetAPI Top 1M, or `in_top_1m` false."""
        return self._get("domain-rank", domain=domain)

    def _get(self, method: str, **params: str) -> dict[str, Any]:
        query = {"method": method, "source": "opencti", **params}
        try:
            response = self._session.get(self._url, params=query, timeout=self._timeout)
        except requests.RequestException as err:
            raise DataRetrievalError(f"Could not reach the NetAPI API: {err}") from err

        try:
            body = response.json()
        except ValueError as err:
            raise NetAPIError(
                response.status_code, "not_json", "the response is not JSON"
            ) from err
        if response.status_code >= 400 or not isinstance(body, dict):
            error = body.get("error") if isinstance(body, dict) else None
            error = error if isinstance(error, dict) else {}
            message = str(error.get("message") or response.reason or "unknown error")
            if response.status_code == 429 and response.headers.get("Retry-After"):
                message += f" (retry after {response.headers['Retry-After']} s)"
            raise NetAPIError(
                response.status_code, str(error.get("code") or "http_error"), message
            )
        return body
