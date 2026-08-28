"""HTTP client for the macadress.com MAC address API.

Wraps ``GET /v1/mac/{mac}`` (Bearer authenticated). Methods return parsed JSON
and raise :class:`MacadressAPIError` on any failure; business parsing belongs in
the connector, not here.
"""

from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class MacadressAPIError(Exception):
    """Raised when the macadress.com API returns an error or is unreachable."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class MacadressClient:
    # Conservative default timeouts (connect, read).
    _TIMEOUT = (10, 30)
    _USER_AGENT = "OpenCTI-Connector (macadress.com)"

    def __init__(self, helper, base_url: str, api_key: str) -> None:
        self.helper = helper
        self.base_url = str(base_url).rstrip("/")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": self._USER_AGENT,
            }
        )

        # Retry transient/server errors, honouring Retry-After on 429.
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

    def lookup(self, mac: str) -> dict:
        """Return the macadress.com analysis for ``mac`` as a dict.

        Raises :class:`MacadressAPIError` on transport failure, a non-200
        response (400 / 401 / 403 / 429 / 5xx) or a non-JSON body.
        """
        url = f"{self.base_url}/v1/mac/{quote(mac, safe='')}"
        try:
            resp = self.session.get(url, timeout=self._TIMEOUT)
        except requests.exceptions.RequestException as exc:
            raise MacadressAPIError(f"Request to macadress.com failed: {exc}") from exc

        self.helper.connector_logger.debug(
            "[API] Request",
            {"url": url, "status": resp.status_code},
        )

        if resp.status_code == 400:
            raise MacadressAPIError(f"{mac} is not a valid MAC address", 400)
        if resp.status_code in (401, 403):
            raise MacadressAPIError(
                "macadress.com rejected the API key "
                f"(HTTP {resp.status_code}). Check MACADRESS_API_KEY.",
                resp.status_code,
            )
        if resp.status_code == 429:
            raise MacadressAPIError(
                "macadress.com rate limit or monthly quota exceeded (HTTP 429)",
                429,
            )
        if resp.status_code >= 400:
            raise MacadressAPIError(
                f"macadress.com API error (HTTP {resp.status_code}): "
                f"{resp.text[:300]}",
                resp.status_code,
            )

        try:
            return resp.json()
        except ValueError as exc:
            raise MacadressAPIError(
                "macadress.com returned a non-JSON response "
                f"(HTTP {resp.status_code})",
                resp.status_code,
            ) from exc
