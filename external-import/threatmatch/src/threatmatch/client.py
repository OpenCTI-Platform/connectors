import time
from functools import wraps
from http import HTTPMethod
from typing import Any, Callable

import requests
from pycti import OpenCTIConnectorHelper
from requests import HTTPError


class ThreatMatchClient:
    """
    Python client for the ThreatMatch API, with automatic token refresh and context support.

    Usage:
        with ThreatMatchClient(base_url, client_id, client_secret) as client:
            profiles = client.get_profiles()
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        client_id: str,
        client_secret: str,
    ):
        self.helper = helper
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

    @staticmethod
    def _with_token_refresh(
        func: Callable[..., Any],
    ) -> Callable[..., requests.Response]:
        """
        Decorator to handle token refresh on 401 Unauthorized responses.
        Retries once after refreshing the token.
        """

        @wraps(func)
        def wrapper(
            self: "ThreatMatchClient", *args: Any, **kwargs: Any
        ) -> dict[str, Any]:
            self._ensure_token()
            try:
                return func(self, *args, **kwargs)
            except HTTPError as e:
                if e.response.status_code == 401:
                    self._refresh_token()
                    return func(self, *args, **kwargs)
                else:
                    self.helper.connector_logger.error(
                        "Error in ThreatMatch API request",
                        {
                            "error": str(e),
                            "message": e.response.json(),
                            "args": args,
                            "kwargs": kwargs,
                        },
                    )
                    return e.response.json()

        return wrapper

    @_with_token_refresh
    def _request(self, method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
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
        headers["Accept"] = "application/json"
        response = self.session.request(
            method=method, url=url, headers=headers, **kwargs
        )
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise HTTPError(
                "Error in ThreatMatch API",
                {**kwargs, "error": data},
            )
        return data

    def get_profile_ids(self, import_from_date: str) -> list[int]:
        return self._request(
            method=HTTPMethod.GET,
            endpoint="/api/profiles/all",
            params={"mode": "compact", "date_since": import_from_date},
        ).get("list", [])

    def get_alert_ids(self, import_from_date: str) -> list[int]:
        return self._request(
            method=HTTPMethod.GET,
            endpoint="/api/alerts/all",
            params={"mode": "compact", "date_since": import_from_date},
        ).get("list", [])

    def get_taxii_groups(self) -> list[dict[str, Any]]:
        return self._request(
            method=HTTPMethod.GET,
            endpoint="/api/taxii/groups",
        )

    def get_taxii_objects(
        self, group_id: str, stix_type_name: str, modified_after: str
    ) -> dict[str, Any]:
        return self._request(
            method=HTTPMethod.GET,
            endpoint="/api/taxii/objects",
            params={
                "groupId": group_id,
                "stixTypeName": stix_type_name,
                "modifiedAfter": modified_after,
            },
        )

    def get_stix_bundle(self, item_type: str, item_id: str) -> dict[str, Any]:
        return self._request(
            method=HTTPMethod.GET, endpoint=f"/api/stix/{item_type}/{item_id}"
        ).get("objects", [])

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "ThreatMatchClient":
        return self

    def __exit__(self, exc_type: str, exc_value: Exception, traceback: str) -> None:
        self.close()
