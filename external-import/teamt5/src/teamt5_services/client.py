import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests


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
        """Exchange OAuth client credentials for a fresh Bearer token."""
        token_url = f"{self._api_base_url.rstrip('/')}/oauth/token"
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

    def request_data(self, url: str, params=None) -> Optional[dict]:
        """
        Make a GET request to a TeamT5 API URL and return the decoded JSON body.

        :param url: The URL to request data from.
        :param params: Optional dictionary of query parameters.
        :return: The decoded JSON body of the response on success, or ``None`` on failure (HTTP error, network error, or invalid JSON).
        """
        timeout = 15

        try:
            self._ensure_valid_token()
            response = self.session.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            # Small delay so we do not hammer the API on tight pagination loops.
            time.sleep(1)
            return response.json()

        except (
            requests.exceptions.HTTPError,
            requests.ConnectionError,
            requests.ConnectTimeout,
            requests.exceptions.ReadTimeout,
        ) as err:
            self.helper.connector_logger.warning(f"Failed request to: {url} {err}")
        except ValueError as err:
            # ``response.json()`` raises ValueError (a JSONDecodeError) when
            # the body is not valid JSON; treat it like any other transport
            # failure rather than crashing the connector run.
            self.helper.connector_logger.warning(
                f"Failed to decode JSON response from {url}: {err}"
            )
        return None
