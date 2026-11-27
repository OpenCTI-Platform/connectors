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
    ProviderApiAuthenticationError,
    ProviderApiAuthorizationError,
    ProviderApiConnectionError,
    ProviderApiError,
    ProviderApiInvalidResponseError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    RateLimit,
)
from pydantic import SecretStr

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
            ProviderApiAuthenticationError: If Spamhaus rejects the credentials.
            ProviderApiRateLimitError: If the login is throttled (429).
            ProviderApiServerError: If Spamhaus answers with a 5xx.
            ProviderApiTimeoutError: If the login times out.
            ProviderApiConnectionError: If Spamhaus cannot be reached.
            ProviderApiInvalidResponseError: If the answer cannot be used.
        """
        try:
            response = self._post_login()
        except requests.exceptions.Timeout as err:
            raise ProviderApiTimeoutError("Spamhaus login timed out") from err
        except (requests.exceptions.RequestException, ApiClientError) as err:
            raise ProviderApiConnectionError(
                "Spamhaus login failed: the API cannot be reached"
            ) from err

        status = response.status_code
        if status in (400, 401, 403):
            raise ProviderApiAuthenticationError(
                f"Spamhaus rejected the login (HTTP {status}): {CREDENTIALS_HINT}"
            )
        if status == 429:
            raise ProviderApiRateLimitError("Spamhaus throttled the login (HTTP 429)")
        if status >= 500:
            raise ProviderApiServerError(f"Spamhaus login failed with HTTP {status}")
        if status != 200:
            raise ProviderApiInvalidResponseError(
                f"Spamhaus login failed with HTTP {status}"
            )

        self._token, self._token_expires_at = self._read_login_response(response)
        self.logger.info(
            "Spamhaus login succeeded", meta={"expires_at": self._token_expires_at}
        )

    def _send_login(self) -> requests.Response:
        """POST the credentials once."""
        return self._raw_request(
            "POST",
            LOGIN_PATH,
            json={
                "username": self._username.get_secret_value(),
                "password": self._password.get_secret_value(),
                "realm": SPAMHAUS_REALM,
            },
        )

    def _post_login(self) -> requests.Response:
        """POST the credentials, once more after a transient failure.

        ``urllib3`` never retries a POST, so without this a single 5xx or dropped
        connection on the login would make the commercial mode fail for the whole
        run. A rejected login (4xx) is never retried. Nothing is retried when the
        client was built with ``max_retries=0``.
        """
        try:
            response = self._send_login()
        except (requests.exceptions.RequestException, ApiClientError):
            if self._max_retries <= 0:
                raise
        else:
            if response.status_code < 500 or self._max_retries <= 0:
                return response
        self.logger.warning("Spamhaus login failed, trying once more")
        time.sleep(self._backoff_factor)
        return self._send_login()

    @staticmethod
    def _read_login_response(response: requests.Response) -> tuple[SecretStr, float]:
        """Extract the JWT and its expiry; never echo the response in an error."""
        try:
            data = response.json()
        except ValueError as err:
            raise ProviderApiInvalidResponseError(
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
            raise ProviderApiInvalidResponseError(
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
            raise ProviderApiInvalidResponseError(
                "Spamhaus login did not provide a token"
            )
        return {"Authorization": f"Bearer {token.get_secret_value()}"}

    def _send(self, path: str, params: dict[str, Any] | None, *, binary: bool) -> Any:
        """Send one authenticated GET, mapping its failures to provider errors."""
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
        except (ApiClientError, requests.exceptions.RequestException) as err:
            mapped = self._provider_error(err, path, binary=binary)
            if mapped is None:
                raise
            raise mapped from err

    @staticmethod
    def _provider_error(
        err: Exception, path: str, *, binary: bool
    ) -> ProviderApiError | None:
        """Map a request failure to the provider error OpenCTI should get.

        Returns:
            The provider error, or ``None`` when the failure must propagate as is: a
            4xx on a binary download (a sample file) only concerns that file.
        """
        if isinstance(err, ApiForbiddenError):
            return ProviderApiAuthorizationError(
                f"Spamhaus refused the access (HTTP 403): {CREDENTIALS_HINT}"
            )
        if isinstance(err, ApiRateLimitError):
            return ProviderApiRateLimitError(
                "Spamhaus throttles the requests (HTTP 429)"
            )
        if isinstance(err, ApiServerError):
            return ProviderApiServerError(
                f"Spamhaus cannot answer (HTTP {err.status_code})"
            )
        if isinstance(err, ApiClientError):
            # Any other 4xx (400, 404, 422...). On a feed endpoint it means the
            # commercial mode cannot be used, so the caller can fall back.
            if binary:
                return None
            return ProviderApiInvalidResponseError(
                f"Spamhaus rejected the request (HTTP {err.status_code}) for {path}"
            )
        # Below, ``requests`` errors. The order matters: JSONDecodeError and Timeout
        # are subclasses of RequestException (a connect timeout is also a
        # ConnectionError), and the first two are more precise.
        if isinstance(err, requests.exceptions.JSONDecodeError):
            return ProviderApiInvalidResponseError(
                f"Spamhaus returned a body that is not valid JSON for {path}"
            )
        if isinstance(err, requests.exceptions.Timeout):
            return ProviderApiTimeoutError("Spamhaus request timed out")
        return ProviderApiConnectionError(
            "Spamhaus request failed: the API cannot be reached"
        )

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
            raise ProviderApiAuthenticationError(
                f"Spamhaus rejected a fresh token (HTTP 401): {CREDENTIALS_HINT}"
            ) from err

    def get_json(self, path: str, *, params: dict[str, Any] | None = None) -> Any:
        """GET a JSON resource with the JWT, renewing it once on a 401.

        Args:
            path: Endpoint path, e.g. ``/threatfox/v1/iocs``.
            params: Query parameters.

        Returns:
            The parsed JSON body, a ``dict`` or a ``list``.

        Raises:
            ProviderApiAuthenticationError: If the credentials are rejected.
            ProviderApiAuthorizationError: If the account lacks access (403).
            ProviderApiRateLimitError: If the API throttles the requests (429).
            ProviderApiServerError: If the API answers with a 5xx.
            ProviderApiTimeoutError: If a request times out.
            ProviderApiConnectionError: If the API cannot be reached.
            ProviderApiInvalidResponseError: If the API rejects the request with
                another 4xx (400, 404, 422...), or the body is not valid JSON, or
                is neither an object nor an array (e.g. an HTML maintenance page).
            ValueError: If ``path`` points outside the API base URL.
        """
        body = self._authenticated_get(path, params, binary=False)
        if not isinstance(body, (dict, list)):
            raise ProviderApiInvalidResponseError(
                f"Spamhaus returned a body that is not JSON for {path}"
            )
        return body

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
            ProviderApiAuthenticationError: If the credentials are rejected.
            ProviderApiAuthorizationError: If the account lacks access (403).
            ProviderApiRateLimitError: If the API throttles the requests (429).
            ProviderApiServerError: If the API answers with a 5xx.
            ProviderApiTimeoutError: If a request times out.
            ProviderApiConnectionError: If the API cannot be reached.
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
            ProviderApiError: As ``get_json``, plus ``ProviderApiInvalidResponseError``
                if a page has an unexpected shape or the cursor does not advance.
        """
        page_params: dict[str, Any] = {**(params or {}), "page_size": page_size}
        seen_cursors: set[str] = set()
        while True:
            body = self.get_json(path, params=page_params)
            if not isinstance(body, dict) or not isinstance(body.get("items"), list):
                raise ProviderApiInvalidResponseError(
                    f"Spamhaus returned an unexpected page for {path}"
                )
            if body["items"]:
                yield body["items"]

            cursor = self._next_cursor(body.get("meta"), path)
            if cursor is None:
                return
            if cursor in seen_cursors:
                raise ProviderApiInvalidResponseError(
                    f"Spamhaus returned no usable next cursor for {path}"
                )
            seen_cursors.add(cursor)
            page_params = {**page_params, "after": cursor}

    def _next_cursor(self, meta: Any, path: str) -> str | None:
        """Return the cursor of the next page, or ``None`` on the last page.

        A missing ``meta`` or ``next_page`` means the last page. Any other shape is
        refused, so a malformed page cannot end an import early as if it had finished.

        Raises:
            ProviderApiInvalidResponseError: If ``meta``, ``next_page`` or ``next_cursor``
                has the wrong type, or no cursor can be read.
        """
        if meta is None:
            return None
        if not isinstance(meta, dict):
            raise ProviderApiInvalidResponseError(
                f"Spamhaus returned an unexpected page metadata for {path}"
            )
        next_page = meta.get("next_page")
        if next_page is None or next_page == "":
            return None
        next_cursor = meta.get("next_cursor")
        if not isinstance(next_page, str) or not (
            next_cursor is None or isinstance(next_cursor, str)
        ):
            raise ProviderApiInvalidResponseError(
                f"Spamhaus returned an unexpected next page for {path}"
            )
        cursor = next_cursor or self._cursor_from(next_page)
        if not cursor:
            raise ProviderApiInvalidResponseError(
                f"Spamhaus returned no usable next cursor for {path}"
            )
        return cursor

    @staticmethod
    def _cursor_from(next_page: str) -> str | None:
        """Read the ``after`` cursor from a ``next_page`` relative URI."""
        values = parse_qs(urlparse(next_page).query).get("after")
        return values[0] if values else None
