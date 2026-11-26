import threading
import time
from typing import Optional

import requests
from requests.auth import AuthBase


class TokenRequestError(Exception):
    """A token request failed.

    The original exception is its ``__cause__``: ``requests.RequestException`` for a
    network or HTTP error, ``ValueError`` for a body that is not a JSON object or has
    an invalid ``expires_in``, ``KeyError`` for a body without ``access_token``.

    It is not a ``requests.RequestException``, so that the caller can tell a failed
    token request apart from a failed request to the API.
    """


class JWTClientCredentialAuth(AuthBase):
    """Bearer authentication with a token from an OAuth client-credentials grant.

    The token is requested from ``token_url`` on the first request, then reused
    until it expires. Its lifetime is read from the ``expires_in`` field of the
    token response, not from the token itself. A new token is requested:

    - before a request, when the current one expires within ``leeway`` seconds;
    - once, when the server answers 401 (revoked token, clock skew...): the
      request is then sent again once with the new token.

    A failed token request raises a ``TokenRequestError``, from the request that
    needed the token.
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        leeway: int = 60,
        default_expires_in: int = 3600,
        timeout: int = 10,
    ) -> None:
        """
        :param token_url: The OAuth token endpoint.
        :param client_id: The OAuth client id.
        :param client_secret: The OAuth client secret.
        :param leeway: Refresh the token this many seconds before it expires.
        :param default_expires_in: The token lifetime, in seconds, when the token
            response has no ``expires_in``.
        :param timeout: The timeout, in seconds, of the token request.
        """
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.leeway = leeway
        self.default_expires_in = default_expires_in
        self.timeout = timeout
        self.access_token: Optional[str] = None
        # ``time.monotonic()`` deadline, unaffected by changes of the system clock
        self.expires_at: Optional[float] = None
        self._lock = threading.Lock()

    # --- token handling -------------------------------------------------
    def _is_expired(self) -> bool:
        return self.expires_at is None or time.monotonic() >= (
            self.expires_at - self.leeway
        )

    def _refresh(self, stale_token: Optional[str]) -> None:
        """Request a new token, unless another thread already replaced ``stale_token``.

        :raises TokenRequestError: If the token request fails.
        """
        with self._lock:
            if self.access_token != stale_token:
                return
            try:
                access_token, expires_in = self._request_token()
            except (requests.RequestException, ValueError, KeyError) as err:
                raise TokenRequestError(
                    f"Failed to obtain a token from {self.token_url}: {err}"
                ) from err
            self.access_token = access_token
            self.expires_at = time.monotonic() + expires_in

    def _request_token(self) -> tuple[str, int]:
        """Request a token, and return it with its lifetime in seconds."""
        # Plain ``requests.post``, not the session that uses this auth, which would
        # call this auth again
        response = requests.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Token response is not a JSON object")
        access_token = data["access_token"]
        expires_in = data.get("expires_in", self.default_expires_in)
        try:
            expires_in = int(expires_in)
        except (TypeError, ValueError) as err:
            raise ValueError(f"Invalid expires_in: {expires_in!r}") from err
        return access_token, expires_in

    # --- requests integration -------------------------------------------
    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        token = self.access_token
        if self._is_expired():  # proactive refresh
            self._refresh(token)
        request.headers["Authorization"] = f"Bearer {self.access_token}"
        request.register_hook("response", self._retry_on_401)
        return request

    def _retry_on_401(self, response: requests.Response, **kwargs) -> requests.Response:
        if response.status_code != 401:
            return response
        sent = response.request.headers.get("Authorization", "").removeprefix("Bearer ")
        self._refresh(sent)  # reactive refresh

        response.content  # drain and release the connection
        response.close()

        retry = response.request.copy()
        retry.headers["Authorization"] = f"Bearer {self.access_token}"
        # ``adapter.send`` does not run the hooks again: a single retry
        new = response.connection.send(retry, **kwargs)
        new.history.append(response)
        new.request = retry
        return new
