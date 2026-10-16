import time
from typing import Any

import requests

TOKEN_URL_TEMPLATE = "https://{vanity_domain}.zslogin.net/oauth2/v1/token"
TOKEN_AUDIENCE = "https://api.zscaler.com"
ZIA_API_PATH = "/zia/api/v1"

# Refresh the token slightly before it expires to avoid failing in-flight requests
TOKEN_EXPIRY_MARGIN = 60  # seconds
DEFAULT_RATE_LIMIT_DELAY = 65  # seconds


class ZscalerAuthenticationError(Exception):
    """Raised when an access token cannot be obtained from ZIdentity."""


class ZscalerClient:
    """Minimal client for the Zscaler Internet Access API through Zscaler OneAPI.

    Authenticates with the OAuth 2.0 client credentials flow against ZIdentity,
    caches the access token until it expires and retries once with a new token
    on HTTP 401.
    """

    def __init__(
        self,
        logger: Any,  # pycti connector logger, which has no public type
        client_id: str,
        client_secret: str,
        vanity_domain: str,
        cloud: str | None = None,
        ssl_verify: bool = True,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.logger = logger
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = TOKEN_URL_TEMPLATE.format(vanity_domain=vanity_domain)
        api_host = f"api.{cloud}.zsapi.net" if cloud else "api.zsapi.net"
        self.base_url = f"https://{api_host}{ZIA_API_PATH}"
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.max_retries = max_retries

        self.session = requests.Session()
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0

    def authenticate(self) -> None:
        """Request a new access token from ZIdentity.

        Raises:
            ZscalerAuthenticationError: If the token request fails.
        """
        self.logger.info("Requesting Zscaler OneAPI access token...")
        try:
            response = self.session.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": TOKEN_AUDIENCE,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
                verify=self.ssl_verify,
            )
        except requests.RequestException as err:
            raise ZscalerAuthenticationError(
                "Unable to reach the ZIdentity token endpoint"
            ) from err

        if not response.ok:
            raise ZscalerAuthenticationError(
                f"ZIdentity token request failed with status {response.status_code}: "
                f"{response.text}"
            )

        try:
            body = response.json()
            self._access_token = body["access_token"]
            expires_in = int(body.get("expires_in", 3600))
        except (ValueError, KeyError) as err:
            raise ZscalerAuthenticationError(
                "Unexpected response from the ZIdentity token endpoint"
            ) from err

        self._token_expires_at = time.time() + expires_in - TOKEN_EXPIRY_MARGIN
        self.logger.info(
            "Zscaler OneAPI access token obtained", {"expires_in": expires_in}
        )

    def _get_token(self) -> str:
        if not self._access_token or time.time() >= self._token_expires_at:
            self.authenticate()
        return self._access_token

    @staticmethod
    def _rate_limit_delay(response: requests.Response) -> int:
        for header in ("x-ratelimit-reset", "Retry-After"):
            value = response.headers.get(header)
            if value and value.isdigit():
                return int(value)
        return DEFAULT_RATE_LIMIT_DELAY

    def request(
        self, method: str, path: str, **kwargs: Any
    ) -> requests.Response | None:
        """Send a request to the ZIA API.

        Handles token expiration (HTTP 401) and rate limiting (HTTP 429).

        Returns:
            The last response received, whatever its status code, or None when
            no response could be obtained (authentication or network failure).
        """
        url = f"{self.base_url}{path}"
        token_refreshed = False
        response = None

        for attempt in range(1, self.max_retries + 1):
            try:
                headers = {
                    "Authorization": f"Bearer {self._get_token()}",
                    "Content-Type": "application/json",
                }
                response = self.session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.ssl_verify,
                    **kwargs,
                )
            except ZscalerAuthenticationError as err:
                self.logger.error("Zscaler authentication failed", {"error": str(err)})
                return None
            except requests.RequestException as err:
                self.logger.error(
                    "Zscaler API request failed",
                    {"method": method, "path": path, "error": str(err)},
                )
                return None

            if response.status_code == 401 and not token_refreshed:
                self.logger.warning(
                    "Zscaler access token rejected, requesting a new one",
                    {"method": method, "path": path},
                )
                self._access_token = None
                token_refreshed = True
                continue

            if response.status_code == 429 and attempt < self.max_retries:
                delay = self._rate_limit_delay(response)
                self.logger.warning(
                    "Zscaler API rate limit exceeded, waiting before retrying",
                    {"delay": delay, "attempt": attempt},
                )
                time.sleep(delay)
                continue

            return response

        return response
