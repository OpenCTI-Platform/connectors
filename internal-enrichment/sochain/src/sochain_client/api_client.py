"""HTTP client for the SoChain API v3.

Wraps the two address lookups the connector uses. Methods return the ``data``
object of a ``{"status": "success", "data": {...}}`` answer and raise
:class:`SochainAPIError` on any failure; shaping belongs in the connector.
"""

from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SochainAPIError(Exception):
    """Raised when the SoChain API returns an error or is unreachable."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class SochainClient:
    # Conservative default timeouts (connect, read).
    _TIMEOUT = (10, 30)
    _USER_AGENT = "OpenCTI-Connector (SoChain)"

    def __init__(self, helper, base_url: str, api_key: str | None = None) -> None:
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")
        # The key is optional: lookups work without one, up to a daily limit.
        # Sent per request, and requests never follow redirects (see _get),
        # so the key cannot be replayed to another host.
        self._auth_header = {"API-KEY": api_key} if api_key else {}

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": self._USER_AGENT,
            }
        )

        # Retry transient errors, honouring Retry-After on 429 and 503.
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _get(self, path: str) -> dict:
        url = f"{self.base_url}/{path}"
        try:
            resp = self.session.get(
                url,
                headers=self._auth_header,
                timeout=self._TIMEOUT,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            raise SochainAPIError(f"Request to SoChain failed: {exc}") from exc

        self.helper.connector_logger.debug(
            "[API] Request",
            {"url": url, "status": resp.status_code},
        )

        try:
            body = resp.json()
        except ValueError:
            body = None

        message = None
        if isinstance(body, dict) and isinstance(body.get("data"), dict):
            message = body["data"].get("error_message")

        if 300 <= resp.status_code < 400:
            raise SochainAPIError(
                f"SoChain answered with a redirect (HTTP {resp.status_code}); "
                "not followed",
                resp.status_code,
            )
        if resp.status_code == 401:
            raise SochainAPIError(
                "SoChain refused the request (HTTP 401): "
                f"{message or 'check SOCHAIN_API_KEY'}",
                401,
            )
        if resp.status_code == 429:
            raise SochainAPIError(
                "SoChain rate limit reached (HTTP 429): "
                f"{message or 'add an API key from https://sochain.com/dashboard'}",
                429,
            )
        if resp.status_code >= 400:
            raise SochainAPIError(
                f"SoChain API error (HTTP {resp.status_code}): "
                f"{message or resp.text[:300]}",
                resp.status_code,
            )
        if not isinstance(body, dict) or body.get("status") != "success":
            raise SochainAPIError(
                f"SoChain returned an unexpected answer (HTTP {resp.status_code})",
                resp.status_code,
            )
        return body.get("data") or {}

    def address_summary(self, network: str, address: str) -> dict:
        """Return balances, transaction counts and first and last activity."""
        return self._get(f"address_summary/{network}/{quote(address, safe='')}")

    def address_poisoning(self, network: str, address: str) -> dict:
        """Return the look-alike addresses that sent this address dust."""
        return self._get(f"address_poisoning/{network}/{quote(address, safe='')}")
