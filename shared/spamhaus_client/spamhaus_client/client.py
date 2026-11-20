"""HTTP client of the Spamhaus commercial API (JWT authentication)."""

from __future__ import annotations

import time
from collections.abc import Generator
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests
from connectors_sdk import (
    ApiClientError,
    ApiForbiddenError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
    BaseClientApi,
    RateLimit,
)
from pydantic import SecretStr
from spamhaus_client.exceptions import (
    SpamhausAuthenticationError,
    SpamhausInvalidResponseError,
    SpamhausUnavailableError,
)

SPAMHAUS_API_URL = "https://api.spamhaus.com"
SPAMHAUS_REALM = "abusech"
LOGIN_PATH = "/v1/login"
CREDENTIALS_HINT = "check the Spamhaus credentials"


def build_user_agent(connector_name: str, version: str) -> str:
    """Build the explicit User-Agent sent on every request.

    Spamhaus rejects the default ``Python-urllib`` User-Agent with a 403.

    Args:
        connector_name: Short connector name, e.g. ``threatfox``.
        version: Connector version.

    Returns:
        ``OpenCTI-<connector_name>/<version>``.
    """
    return f"OpenCTI-{connector_name}/{version}"


class SpamhausClient(BaseClientApi):
    """Client of the Spamhaus commercial API, authenticated with a reusable JWT.

    The client logs in once (``POST /v1/login``, realm ``abusech``), reuses the JWT
    until ``token_refresh_margin`` seconds before its expiry, and logs in again once
    when the API answers 401. It never logs in per request.

    Neither the password, the JWT nor the login response is logged or put in an
    exception message.

    Args:
        username: Spamhaus abuse.ch API account username.
        password: Spamhaus abuse.ch API account password.
        connector_name: Short connector name, used in the User-Agent.
        connector_version: Connector version, used in the User-Agent.
        base_url: API base URL.
        token_refresh_margin: Seconds before expiry from which the JWT is renewed.
        timeout: Request timeout in seconds.
        ssl_verify: Whether to verify SSL certificates.
        max_retries: Retries for transient errors (408, 429, 5xx).
        backoff_factor: Exponential backoff factor between retries.
        rate_limit: Optional proactive rate limit.
    """

    def __init__(
        self,
        *,
        username: SecretStr,
        password: SecretStr,
        connector_name: str,
        connector_version: str,
        base_url: str = SPAMHAUS_API_URL,
        token_refresh_margin: int = 300,
        timeout: int = 60,
        ssl_verify: bool = True,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        rate_limit: RateLimit | str | None = None,
    ) -> None:
        """Initialize the client, without any network call."""
        super().__init__(
            base_url,
            timeout=timeout,
            ssl_verify=ssl_verify,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            rate_limit=rate_limit,
        )
        self._username = username
        self._password = password
        self._user_agent = build_user_agent(connector_name, connector_version)
        self._token_refresh_margin = token_refresh_margin
        self._token: SecretStr | None = None
        self._token_expires_at: float = 0.0

    @property
    def session_headers(self) -> dict[str, str]:
        """Return the explicit User-Agent, set on every request."""
        return {"User-Agent": self._user_agent}

    def login(self) -> None:
        """Log in and store the JWT.

        Raises:
            SpamhausAuthenticationError: If Spamhaus rejects the credentials.
            SpamhausUnavailableError: If the login cannot be done (network, 5xx).
        """
        try:
            response = self._raw_request(
                "POST",
                LOGIN_PATH,
                json={
                    "username": self._username.get_secret_value(),
                    "password": self._password.get_secret_value(),
                    "realm": SPAMHAUS_REALM,
                },
            )
        except (requests.exceptions.RequestException, ApiClientError) as err:
            raise SpamhausUnavailableError(
                "Spamhaus login failed: the API cannot be reached"
            ) from err

        status = response.status_code
        if status in (400, 401, 403):
            raise SpamhausAuthenticationError(
                f"Spamhaus rejected the login (HTTP {status}): {CREDENTIALS_HINT}"
            )
        if status != 200:
            raise SpamhausUnavailableError(f"Spamhaus login failed with HTTP {status}")

        self._token, self._token_expires_at = self._read_login_response(response)
        self.logger.info(
            "Spamhaus login succeeded", meta={"expires_at": self._token_expires_at}
        )

    @staticmethod
    def _read_login_response(response: requests.Response) -> tuple[SecretStr, float]:
        """Extract the JWT and its expiry; never echo the response in an error."""
        try:
            data = response.json()
        except ValueError as err:
            raise SpamhausUnavailableError(
                "Spamhaus login returned a body that is not JSON"
            ) from err
        token = data.get("token") if isinstance(data, dict) else None
        expires = data.get("expires") if isinstance(data, dict) else None
        if (
            not isinstance(token, str)
            or not token
            or isinstance(expires, bool)
            or not isinstance(expires, (int, float))
        ):
            raise SpamhausUnavailableError(
                "Spamhaus login returned an unexpected response"
            )
        return SecretStr(token), float(expires)

    def _bearer_headers(self) -> dict[str, str]:
        """Return the Authorization header, logging in when the token is missing or old."""
        if (
            self._token is None
            or time.time() >= self._token_expires_at - self._token_refresh_margin
        ):
            self.login()
        token = self._token
        if token is None:
            raise SpamhausUnavailableError("Spamhaus login did not provide a token")
        return {"Authorization": f"Bearer {token.get_secret_value()}"}

    def _send(self, path: str, params: dict[str, Any] | None, *, binary: bool) -> Any:
        """Send one authenticated GET and map its failures to commercial errors."""
        headers = self._bearer_headers()
        try:
            if binary:
                response = self._raw_request(
                    "GET", path, params=params, headers=headers
                )
                if not response.ok:
                    self._raise_for_status(response, "GET", path)
                return response.content
            return self._get(path, params=params, headers=headers)
        except ApiUnauthorizedError:
            raise
        except ApiForbiddenError as err:
            raise SpamhausAuthenticationError(
                f"Spamhaus refused the access (HTTP 403): {CREDENTIALS_HINT}"
            ) from err
        except (ApiRateLimitError, ApiServerError) as err:
            raise SpamhausUnavailableError(
                f"Spamhaus cannot answer (HTTP {err.status_code})"
            ) from err
        except requests.exceptions.RequestException as err:
            raise SpamhausUnavailableError(
                "Spamhaus request failed: the API cannot be reached"
            ) from err

    def _ensure_same_origin(self, path: str) -> None:
        """Refuse a path that resolves outside the configured API origin.

        ``BaseClientApi`` returns an absolute URL unchanged, so a caller passing one
        would send the bearer token to another host. Checked before any login or
        request, so no credential leaves for a foreign origin.

        Raises:
            ValueError: If the path does not resolve to the API base URL origin.
        """
        base = urlparse(self._base_url)
        target = urlparse(self._build_url(path))
        if (target.scheme, target.netloc) != (base.scheme, base.netloc):
            raise ValueError(
                "Spamhaus requests must use a path relative to the API base URL"
            )

    def _authenticated_get(
        self, path: str, params: dict[str, Any] | None, *, binary: bool
    ) -> Any:
        """GET with the JWT, logging in again once when the API answers 401."""
        self._ensure_same_origin(path)
        try:
            return self._send(path, params, binary=binary)
        except ApiUnauthorizedError:
            self.logger.info("Spamhaus token rejected, logging in again")
            self._token = None
            self.login()
        try:
            return self._send(path, params, binary=binary)
        except ApiUnauthorizedError as err:
            raise SpamhausAuthenticationError(
                f"Spamhaus rejected a fresh token (HTTP 401): {CREDENTIALS_HINT}"
            ) from err

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """GET a JSON resource with the JWT, renewing it once on a 401.

        Args:
            path: Endpoint path, e.g. ``/threatfox/v1/iocs``.
            params: Query parameters.

        Returns:
            The parsed JSON body.

        Raises:
            SpamhausAuthenticationError: If the credentials are rejected.
            SpamhausUnavailableError: If the API cannot answer.
            ValueError: If ``path`` points outside the API base URL.
        """
        return self._authenticated_get(path, params, binary=False)

    def get_bytes(self, path: str, *, params: dict[str, Any] | None = None) -> bytes:
        """GET a binary resource (e.g. a sample file) with the JWT.

        Same token reuse, single re-login on 401 and error mapping as ``get_json``.
        The body is returned as is, whatever its Content-Type.

        Args:
            path: Endpoint path, e.g. ``/urlhaus/v1/files/samples/<sha256>``.
            params: Query parameters.

        Returns:
            The raw response body.

        Raises:
            SpamhausAuthenticationError: If the credentials are rejected.
            SpamhausUnavailableError: If the API cannot answer.
            ValueError: If ``path`` points outside the API base URL.
        """
        content: bytes = self._authenticated_get(path, params, binary=True)
        return content

    def paginate(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        page_size: int = 100,
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Iterate over every page of a cursor-paginated endpoint.

        Sends ``page_size`` and, from the second page, ``after`` (``meta.next_cursor``
        of the previous page), until a page has no ``meta.next_page``.

        Args:
            path: Endpoint path, e.g. ``/threatfox/v1/iocs``.
            params: Query parameters such as ``since``.
            page_size: Items per page (1 to 100).

        Yields:
            The ``items`` of each page.

        Raises:
            SpamhausAuthenticationError: If the credentials are rejected.
            SpamhausUnavailableError: If the API cannot answer.
            SpamhausInvalidResponseError: If a page has an unexpected shape or
                the cursor does not advance.
        """
        page_params: dict[str, Any] = {**(params or {}), "page_size": page_size}
        seen_cursors: set[str] = set()
        while True:
            body = self.get_json(path, params=page_params)
            if not isinstance(body, dict) or not isinstance(body.get("items"), list):
                raise SpamhausInvalidResponseError(
                    f"Spamhaus returned an unexpected page for {path}"
                )
            if body["items"]:
                yield body["items"]

            meta = body.get("meta")
            meta = meta if isinstance(meta, dict) else {}
            if not meta.get("next_page"):
                return
            cursor = meta.get("next_cursor") or self._cursor_from(meta["next_page"])
            if not cursor or cursor in seen_cursors:
                raise SpamhausInvalidResponseError(
                    f"Spamhaus returned no usable next cursor for {path}"
                )
            seen_cursors.add(cursor)
            page_params = {**page_params, "after": cursor}

    @staticmethod
    def _cursor_from(next_page: str) -> str | None:
        """Read the ``after`` cursor from a ``next_page`` relative URI."""
        values = parse_qs(urlparse(next_page).query).get("after")
        return values[0] if values else None
