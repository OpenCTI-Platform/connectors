import time
from functools import wraps
from http import HTTPMethod
from typing import Callable, Optional, Any

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

        self.token: Optional[str] = None
        self._token_expires_at = 0.0
        self._ensure_token()

    def _refresh_token(self):
        response = self.session.post(
            f"{self.base_url}/api/developers-platform/token",
            json={"client_id": self.client_id, "client_secret": self.client_secret},
        )
        if response.status_code != 200:
            raise Exception(f"ThreatMatch Authentication failed: {response.text}")
        data = response.json()
        self.token = data["access_token"]
        self._token_expires_at = data["expires_at"]

    def _ensure_token(self):
        if not self.token or int(time.time()) > self._token_expires_at:
            self._refresh_token()

    @staticmethod
    def _with_token_refresh(func: Callable) -> Callable:
        """
        Decorator to handle token refresh on 401 Unauthorized responses.
        Retries once after refreshing the token.
        """

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            self._ensure_token()
            response = func(self, *args, **kwargs)
            if response.status_code == 401:
                self._refresh_token()
                response = func(self, *args, **kwargs)
                if response.status_code == 401:  # Check twice to ensure token is valid
                    raise Exception(
                        "Unauthorized (401): Check credentials or token validity."
                    )
            return response

        return wrapper

    @_with_token_refresh
    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        Send an HTTP request to the ThreatMatch API with automatic token management.

        Args:
            method: HTTP verb, e.g., "GET", "POST".
            endpoint: API endpoint (e.g., "/api/profiles/all").
            **kwargs: Extra arguments for requests.request.

        Returns:
            The HTTP response (requests.Response).
        """
        url = self.base_url + endpoint
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.token}"
        return self.session.request(method=method, url=url, headers=headers, **kwargs)

    def get_profile_ids(self, import_from_date: str) -> dict:
        return (
            self._request(
                method=HTTPMethod.GET,
                endpoint="/api/profiles/all",
                json={"mode": "compact", "date_since": import_from_date},
            )
            .json()
            .get("list", [])
        )

    def get_alert_ids(self, import_from_date: str) -> list[int]:
        return (
            self._request(
                method=HTTPMethod.GET,
                endpoint="/api/alerts/all",
                json={"mode": "compact", "date_since": import_from_date},
            )
            .json()
            .get("list", [])
        )

    def get_taxii_groups(self) -> list[dict[str, Any]]:
        return self._request(
            method=HTTPMethod.GET,
            endpoint="/api/taxii/groups",
        ).json()

    def get_taxii_objects(
        self, group_id: str, stix_type_name: str, modified_after: str
    ):
        return self._request(
            method=HTTPMethod.GET,
            endpoint="/api/taxii/objects",
            params={
                "groupId": group_id,
                "stixTypeName": stix_type_name,
                "modifiedAfter": modified_after,
            },
        ).json()

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
