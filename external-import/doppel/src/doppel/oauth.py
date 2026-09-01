import math
import threading
import time
from collections.abc import Callable

import requests
from doppel.constants import DOPPEL_ATTRIBUTION_HEADERS


class OAuthTokenError(requests.RequestException):
    """Raised when Doppel returns an invalid OAuth token response."""


class OAuthTokenProvider:
    """Mint and cache Doppel API V2 client-credentials access tokens."""

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        client_secret: str,
        audience: str,
        timeout: int = 30,
        session: requests.Session | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(DOPPEL_ATTRIBUTION_HEADERS)
        self.clock = clock

        self._access_token: str | None = None
        self._refresh_at = 0.0
        self._lock = threading.Lock()

    def get_token(self) -> str:
        """Return a cached token, minting one when absent or near expiry."""
        with self._lock:
            if self._token_is_fresh():
                assert self._access_token is not None
                return self._access_token
            return self._mint_token()

    def refresh_after_unauthorized(self, rejected_token: str) -> str:
        """Replace a rejected token without causing concurrent refresh storms."""
        with self._lock:
            if (
                self._access_token
                and self._access_token != rejected_token
                and self._token_is_fresh()
            ):
                return self._access_token

            self._access_token = None
            self._refresh_at = 0.0
            return self._mint_token()

    def _token_is_fresh(self) -> bool:
        return bool(self._access_token) and self.clock() < self._refresh_at

    def _mint_token(self) -> str:
        response = self.session.post(
            self.token_url,
            json={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": self.audience,
                "grant_type": "client_credentials",
            },
            timeout=self.timeout,
        )
        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as exc:
            raise OAuthTokenError(
                "Doppel OAuth token response was not valid JSON"
            ) from exc

        if not isinstance(payload, dict):
            raise OAuthTokenError("Doppel OAuth token response must be an object")

        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token.strip():
            raise OAuthTokenError(
                "Doppel OAuth token response did not include an access_token"
            )

        token_type = payload.get("token_type")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise OAuthTokenError(
                "Doppel OAuth token response did not specify Bearer token_type"
            )

        expires_in = payload.get("expires_in")
        if isinstance(expires_in, bool):
            raise OAuthTokenError(
                "Doppel OAuth token response included an invalid expires_in"
            )
        try:
            expires_in_seconds = float(expires_in)
        except (TypeError, ValueError) as exc:
            raise OAuthTokenError(
                "Doppel OAuth token response included an invalid expires_in"
            ) from exc
        if not math.isfinite(expires_in_seconds) or expires_in_seconds <= 0:
            raise OAuthTokenError(
                "Doppel OAuth token response included an invalid expires_in"
            )

        refresh_margin = min(60.0, expires_in_seconds * 0.1)
        self._access_token = access_token.strip()
        self._refresh_at = self.clock() + expires_in_seconds - refresh_margin
        return self._access_token
