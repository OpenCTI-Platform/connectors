import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests


class Teamt5AuthError(Exception):
    """Raised when the OAuth token exchange against TeamT5 fails.

    Surfaced as a dedicated exception (rather than a bare ``Exception``
    or the underlying ``RequestException`` / ``ValueError``) so callers
    — and the operator reading the connector log — can tell an auth-
    setup failure apart from a transient transport hiccup on a
    subsequent data call. ``Teamt5Client.__init__`` invokes
    ``_refresh_token()`` synchronously, so this also propagates as the
    visible startup failure when ``OAuth`` credentials are misconfigured
    or the token endpoint is unreachable.
    """


class Teamt5Client:

    # Safety margin (seconds) subtracted from the OAuth token expiry so we
    # never present a token that is about to flip stale to the API.
    _TOKEN_EXPIRY_MARGIN_SEC = 60

    def __init__(self, helper, config) -> None:
        """
        Initialises the the Teamt5Client.

        :param helper: The OpenCTI connector helper object.
        :param config: The connector configuration object.
        """

        self.helper = helper
        self.config = config

        self.session = requests.Session()

        teamt5_cfg = self.config.teamt5
        self._api_base_url = teamt5_cfg.api_base_url
        self._client_id = (
            teamt5_cfg.client_id.get_secret_value()
            if teamt5_cfg.client_id is not None
            else None
        )
        self._client_secret = (
            teamt5_cfg.client_secret.get_secret_value()
            if teamt5_cfg.client_secret is not None
            else None
        )
        self._api_key = (
            teamt5_cfg.api_key.get_secret_value()
            if teamt5_cfg.api_key is not None
            else None
        )
        self._token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None

        if self._client_id and self._client_secret:
            # OAuth takes precedence when both auth paths are present.
            self._refresh_token()
        elif self._api_key:
            self.session.headers.update({"Authorization": f"Bearer {self._api_key}"})
        # The settings model's validator guarantees one of the two paths is
        # populated, so no further branch is needed here.

    def _refresh_token(self) -> None:
        """Exchange OAuth client credentials for a fresh Bearer token.

        Wraps the token POST + ``response.json()`` decode in a single
        try/except so a failed exchange surfaces as a dedicated
        :class:`Teamt5AuthError` with the underlying cause logged
        in a structured ``meta`` dict instead of crashing the
        connector with an opaque ``requests.exceptions.*`` or
        ``ValueError`` traceback. The narrower categories we already
        care about (HTTP error from ``raise_for_status``, network
        error from ``requests.post``, non-JSON body from
        ``response.json``) all surface through
        :class:`requests.RequestException` /
        :class:`ValueError` — keeping the catch wide ensures any
        future ``requests`` exception subclass added upstream still
        produces an actionable startup log line.
        """
        token_url = f"{self._api_base_url.rstrip('/')}/oauth/token"
        try:
            response = requests.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                timeout=10,
            )
            response.raise_for_status()
            data = response.json()
            self._token = data["access_token"]
            expires_in = int(data.get("expires_in", 3600))
        except (requests.RequestException, ValueError, KeyError) as err:
            # Log the failure context with the structured meta the
            # rest of this connector uses, then re-raise as
            # ``Teamt5AuthError`` so the operator sees a clear
            # auth-startup failure (rather than the raw
            # ``RequestException`` / ``ValueError`` traceback) and
            # the scheduler can apply its standard retry policy.
            self.helper.connector_logger.error(
                "TeamT5 OAuth token exchange failed",
                meta={"token_url": token_url, "error": str(err)},
            )
            raise Teamt5AuthError(
                f"Failed to obtain OAuth token from TeamT5: {err}"
            ) from err
        self._token_expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=max(expires_in - self._TOKEN_EXPIRY_MARGIN_SEC, 0)
        )
        self.session.headers.update({"Authorization": f"Bearer {self._token}"})

    def _ensure_valid_token(self) -> None:
        """Refresh the OAuth token if it is missing or about to expire."""
        if not (self._client_id and self._client_secret):
            return
        if (
            self._token_expires_at is None
            or datetime.now(timezone.utc) >= self._token_expires_at
        ):
            self._refresh_token()

    def request_data(
        self, url: str, params=None, throttle: bool = False
    ) -> Optional[dict]:
        """
        Make a GET request to a TeamT5 API URL and return the decoded JSON body.

        :param url: The URL to request data from.
        :param params: Optional dictionary of query parameters.
        :param throttle: When ``True``, sleep for one second AFTER a
            successful response. Reserved for tight pagination loops
            (``BaseHandler.retrieve_bundle_references``) where back-to-back
            GETs against the same listing endpoint are paced to avoid
            hammering the upstream API. The default ``False`` keeps
            STIX bundle downloads (``BaseHandler.push_objects``,
            ``Teamt5Client._refresh_token`` callers, …) unthrottled —
            on a run with many bundles, an unconditional one-second
            sleep after every GET would silently add minutes to the
            wall-clock time of every cycle.
        :return: The decoded JSON body of the response on success, or ``None`` on failure (HTTP error, network error, or invalid JSON).
        """
        timeout = 15

        try:
            self._ensure_valid_token()
            response = self.session.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            payload = response.json()
            # Only the pagination caller opts into the throttle (see the
            # ``throttle`` argument docstring above) — bundle downloads
            # do NOT pay this cost.
            if throttle:
                time.sleep(1)
            return payload

        # ``requests.RequestException`` is the root of the requests
        # exception hierarchy and covers ``HTTPError`` /
        # ``ConnectionError`` / ``ConnectTimeout`` / ``ReadTimeout``
        # alongside the less-common ``SSLError`` / ``TooManyRedirects``
        # / ``ChunkedEncodingError`` / ``ContentDecodingError`` /
        # ``ProxyError`` / ``MissingSchema`` shapes that the previous
        # narrow tuple let bubble up and crash the run. Catching the
        # root keeps the contract — "transport errors return ``None``,
        # callers handle the failure" — consistent across every
        # ``requests`` exception class current and future.
        except requests.RequestException as err:
            self.helper.connector_logger.warning(f"Failed request to: {url} {err}")
        except ValueError as err:
            # ``response.json()`` raises ValueError (a JSONDecodeError) when
            # the body is not valid JSON; treat it like any other transport
            # failure rather than crashing the connector run.
            self.helper.connector_logger.warning(
                f"Failed to decode JSON response from {url}: {err}"
            )
        return None
