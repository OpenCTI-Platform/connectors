import time

import requests


class ThreatMatchClient:
    """
    Python client for the ThreatMatch API, with automatic token refresh and context support.

    Usage:
        with ThreatMatchClient(base_url, client_id, client_secret) as client:
            profiles = client.get_profiles()
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip("/")  # To avoid double slashes in URLs
        self.client_id = client_id
        self.client_secret = client_secret

        self.session = requests.Session()

        self.token = None
        self._token_expires_at = 0.0
        self._ensure_token()

    def _refresh_token(self) -> None:
        response = self.session.post(
            f"{self.base_url}/api/developers-platform/token",
            json={"client_id": self.client_id, "client_secret": self.client_secret},
        )
        response.raise_for_status()
        data = response.json()
        self.token = data["access_token"]
        self._token_expires_at = data["expires_at"]

    def _ensure_token(self) -> None:
        if not self.token or int(time.time()) > self._token_expires_at:
            self._refresh_token()

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "ThreatMatchClient":
        return self

    def __exit__(self, exc_type: str, exc_value: Exception, traceback: str) -> None:
        self.close()
