import time
from typing import Any

import requests
from tenacity import (
    RetryCallState,
    Retrying,
    retry_if_exception_type,
    retry_if_result,
    stop_after_attempt,
)

TOKEN_URL_TEMPLATE = "https://{vanity_domain}.zslogin.net/oauth2/v1/token"
TOKEN_AUDIENCE = "https://api.zscaler.com"
ZIA_API_PATH = "/zia/api/v1"
LEGACY_API_PATH = "/api/v1"
DEFAULT_LEGACY_API_BASE_URL = "https://zsapi.zscalertwo.net"

# Refresh the token slightly before it expires to avoid failing in-flight requests
TOKEN_EXPIRY_MARGIN = 60  # seconds
DEFAULT_RATE_LIMIT_DELAY = 65  # seconds
# Exponential backoff for transient failures (network errors, HTTP 5xx)
BACKOFF_MULTIPLIER = 5  # seconds
BACKOFF_MAX = 60  # seconds


class ZscalerAuthenticationError(Exception):
    """Raised when the connector cannot authenticate to Zscaler."""


def obfuscate_api_key(api_key: str, timestamp: str) -> str:
    """Obfuscate the legacy API key with the provided timestamp, as the legacy API requires."""
    high = timestamp[-6:]  # The last 6 digits of the timestamp
    low = str(int(high) >> 1).zfill(6)  # Right bitwise shift, padded to 6 digits
    obfuscated_api_key = "".join(api_key[int(digit)] for digit in high)
    obfuscated_api_key += "".join(api_key[int(digit) + 2] for digit in low)
    return obfuscated_api_key


class OneApiAuth:
    """OAuth 2.0 client credentials authentication against ZIdentity (Zscaler OneAPI).

    The access token is cached until shortly before it expires.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        vanity_domain: str,
        cloud: str | None = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = TOKEN_URL_TEMPLATE.format(vanity_domain=vanity_domain)
        api_host = f"api.{cloud}.zsapi.net" if cloud else "api.zsapi.net"
        self.base_url = f"https://{api_host}{ZIA_API_PATH}".rstrip("/")
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0

    def authenticate(self, client: "ZscalerClient") -> None:
        """Request a new access token from ZIdentity.

        Raises:
            ZscalerAuthenticationError: If the token request fails.
        """
        client.logger.info("Requesting Zscaler OneAPI access token...")
        try:
            response = client.session.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "audience": TOKEN_AUDIENCE,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=client.timeout,
                verify=client.ssl_verify,
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
        client.logger.info(
            "Zscaler OneAPI access token obtained", {"expires_in": expires_in}
        )

    def headers(self, client: "ZscalerClient") -> dict[str, str]:
        """Return the authentication headers, requesting a token if needed."""
        if not self._access_token or time.time() >= self._token_expires_at:
            self.authenticate(client)
        return {"Authorization": f"Bearer {self._access_token}"}

    def invalidate(self, client: "ZscalerClient") -> None:
        """Drop the cached token so that the next request gets a new one."""
        self._access_token = None


class LegacyAuth:
    """Deprecated session authentication of the legacy ZIA API.

    Kept for tenants not yet migrated to ZIdentity. Zscaler is removing this
    authentication method: use ``OneApiAuth`` instead.
    """

    def __init__(self, api_base_url: str, username: str, password: str, api_key: str):
        self.base_url = f"{api_base_url.rstrip('/')}{LEGACY_API_PATH}"
        self.username = username
        self.password = password
        self.api_key = api_key
        self._authenticated = False

    def authenticate(self, client: "ZscalerClient") -> None:
        """Open a legacy API session (``JSESSIONID`` cookie).

        Raises:
            ZscalerAuthenticationError: If the session cannot be opened.
        """
        client.logger.info("Opening a Zscaler legacy API session...")
        client.session.cookies.clear()
        timestamp = str(int(time.time() * 1000))
        try:
            response = client.session.post(
                f"{self.base_url}/authenticatedSession",
                json={
                    "username": self.username,
                    "password": self.password,
                    "apiKey": obfuscate_api_key(self.api_key, timestamp),
                    "timestamp": timestamp,
                },
                headers={"Content-Type": "application/json"},
                timeout=client.timeout,
                verify=client.ssl_verify,
            )
        except requests.RequestException as err:
            raise ZscalerAuthenticationError(
                "Unable to reach the Zscaler legacy API"
            ) from err

        if not response.ok:
            raise ZscalerAuthenticationError(
                f"Zscaler legacy authentication failed with status "
                f"{response.status_code}: {response.text}"
            )
        if not client.session.cookies.get("JSESSIONID"):
            raise ZscalerAuthenticationError(
                "Zscaler legacy authentication returned no JSESSIONID cookie"
            )

        self._authenticated = True
        client.logger.info("Zscaler legacy API session opened.")

    def headers(self, client: "ZscalerClient") -> dict[str, str]:
        """Open a session if needed; the session cookie carries the authentication."""
        if not self._authenticated:
            self.authenticate(client)
        return {}

    def invalidate(self, client: "ZscalerClient") -> None:
        """Forget the session so that the next request opens a new one."""
        self._authenticated = False


class ZscalerClient:
    """Minimal client for the Zscaler Internet Access (ZIA) API.

    Authentication is delegated to ``OneApiAuth`` (Zscaler OneAPI) or to the
    deprecated ``LegacyAuth``. A request rejected with HTTP 401 is replayed once
    after re-authenticating. Rate-limited (HTTP 429) and transient (network
    errors, HTTP 5xx) failures are retried with tenacity, independently of the
    re-authentication.
    """

    def __init__(
        self,
        logger: Any,  # pycti connector logger, which has no public type
        auth: OneApiAuth | LegacyAuth,
        ssl_verify: bool = True,
        timeout: int = 30,
        max_retries: int = 5,
    ):
        self.logger = logger
        self.auth = auth
        self.base_url = auth.base_url.rstrip("/")
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.max_retries = max_retries

        self.session = requests.Session()

    def authenticate(self) -> None:
        """Authenticate to Zscaler.

        Raises:
            ZscalerAuthenticationError: If authentication fails.
        """
        self.auth.authenticate(self)

    @staticmethod
    def _rate_limit_delay(response: requests.Response) -> int:
        for header in ("x-ratelimit-reset", "Retry-After"):
            value = response.headers.get(header)
            if value and value.isdigit():
                return int(value)
        return DEFAULT_RATE_LIMIT_DELAY

    @staticmethod
    def _is_retryable_response(response: requests.Response) -> bool:
        return response.status_code == 429 or response.status_code >= 500

    def _wait(self, retry_state: RetryCallState) -> float:
        outcome = retry_state.outcome
        if outcome is not None and not outcome.failed:
            response = outcome.result()
            if response.status_code == 429:
                return self._rate_limit_delay(response)
        return min(
            BACKOFF_MULTIPLIER * 2 ** (retry_state.attempt_number - 1), BACKOFF_MAX
        )

    def _log_retry(self, retry_state: RetryCallState) -> None:
        outcome = retry_state.outcome
        if outcome is not None and outcome.failed:
            reason = str(outcome.exception())
        else:
            reason = f"HTTP {outcome.result().status_code}"
        self.logger.warning(
            "Zscaler API request failed, retrying",
            {
                "reason": reason,
                "attempt": retry_state.attempt_number,
                "delay": retry_state.upcoming_sleep,
            },
        )

    def _send(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Send one request, replaying it once after re-authenticating on HTTP 401."""
        response = self._send_authenticated(method, url, **kwargs)
        if response.status_code == 401:
            self.logger.warning(
                "Zscaler authentication rejected, re-authenticating",
                {"method": method, "url": url},
            )
            self.auth.invalidate(self)
            response = self._send_authenticated(method, url, **kwargs)
        return response

    def _send_authenticated(
        self, method: str, url: str, **kwargs: Any
    ) -> requests.Response:
        headers = {"Content-Type": "application/json", **self.auth.headers(self)}
        return self.session.request(
            method,
            url,
            headers=headers,
            timeout=self.timeout,
            verify=self.ssl_verify,
            **kwargs,
        )

    def request(
        self, method: str, path: str, **kwargs: Any
    ) -> requests.Response | None:
        """Send a request to the ZIA API.

        Handles authentication expiry (HTTP 401), rate limiting (HTTP 429) and
        transient failures (network errors, HTTP 5xx).

        Returns:
            The last response received, whatever its status code, or None when
            no response could be obtained (authentication or network failure).
        """
        url = f"{self.base_url}{path}"
        retrying = Retrying(
            retry=(
                retry_if_result(self._is_retryable_response)
                | retry_if_exception_type(requests.RequestException)
            ),
            stop=stop_after_attempt(self.max_retries),
            wait=self._wait,
            before_sleep=self._log_retry,
            # Once retries are exhausted, hand back the last response (or None)
            retry_error_callback=lambda state: (
                None if state.outcome.failed else state.outcome.result()
            ),
        )
        try:
            response = retrying(self._send, method, url, **kwargs)
        except ZscalerAuthenticationError as err:
            self.logger.error("Zscaler authentication failed", {"error": str(err)})
            return None

        if response is None:
            self.logger.error(
                "Zscaler API request failed", {"method": method, "path": path}
            )
        return response
