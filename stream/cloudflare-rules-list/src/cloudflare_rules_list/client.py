"""Cloudflare Rules Lists API client.

Documentation:
https://developers.cloudflare.com/api/resources/rules/subresources/lists/
"""

import json
import time
from typing import Any, Optional

import requests


class CloudflareAPIError(Exception):
    """Exception raised for Cloudflare API errors."""


class CloudflareRulesListClient:
    """Client for the Cloudflare Rules Lists API."""

    BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(
        self,
        account_id: str,
        api_token: str,
        timeout: int = 60,
        base_url: Optional[str] = None,
    ):
        """Initialize the client.

        Args:
            account_id: Cloudflare account ID.
            api_token: API token (Bearer auth).
            timeout: Default request timeout in seconds.
            base_url: Override the Cloudflare API base URL (for testing or a
                compatible gateway). Defaults to the public Cloudflare API.
        """
        self.account_id = account_id
        self.api_token = api_token
        self.timeout = timeout
        self.base_url = (base_url or self.BASE_URL).rstrip("/")
        self._session = requests.Session()
        self._session.verify = True  # explicit for security scanners
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            }
        )

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Any] = None,
        timeout: Optional[int] = None,
    ) -> dict:
        """Make an API request to Cloudflare and return the parsed JSON body."""
        url = f"{self.base_url}/accounts/{self.account_id}{endpoint}"
        request_timeout = timeout or self.timeout

        try:
            response = self._session.request(
                method=method,
                url=url,
                json=data,
                timeout=request_timeout,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            error_msg = str(exc)
            err_response = getattr(exc, "response", None)
            if err_response is not None:
                try:
                    error_data = err_response.json()
                    if "errors" in error_data:
                        error_msg = str(error_data["errors"])
                except (json.JSONDecodeError, ValueError):
                    error_msg = err_response.text
            raise CloudflareAPIError(f"API request failed: {error_msg}") from exc

        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise CloudflareAPIError(
                f"Invalid JSON in Cloudflare response: {response.text[:200]}"
            ) from exc

    def list_lists(self) -> list[dict]:
        """List all rules lists in the account."""
        response = self._make_request("GET", "/rules/lists")
        return response.get("result", [])

    def get_list(self, list_id: str) -> dict:
        """Get a specific list's metadata."""
        response = self._make_request("GET", f"/rules/lists/{list_id}")
        return response.get("result", {})

    def get_list_items(self, list_id: str, cursor: Optional[str] = None) -> dict:
        """Get a page of items from a list."""
        endpoint = f"/rules/lists/{list_id}/items"
        if cursor:
            endpoint += f"?cursor={cursor}"
        return self._make_request("GET", endpoint)

    def get_all_list_items(self, list_id: str) -> list[dict]:
        """Get all items from a list, following pagination cursors."""
        all_items: list[dict] = []
        cursor = None

        while True:
            response = self.get_list_items(list_id, cursor)
            all_items.extend(response.get("result", []))

            result_info = response.get("result_info", {})
            cursor = result_info.get("cursors", {}).get("after")
            if not cursor:
                break

        return all_items

    def replace_list_items(self, list_id: str, items: list[dict]) -> dict:
        """Replace ALL items in a list with the provided items (snapshot).

        Args:
            list_id: The list ID.
            items: Items in the kind-specific format, e.g. for an IP list:
                ``[{"ip": "192.0.2.1"}, {"ip": "10.0.0.0/8"}]``.

        Returns:
            Operation result, including an ``operation_id`` for the async bulk job.
        """
        response = self._make_request(
            "PUT", f"/rules/lists/{list_id}/items", data=items, timeout=300
        )
        return response.get("result", {})

    def get_bulk_operation(self, operation_id: str) -> dict:
        """Get the status of a bulk operation."""
        response = self._make_request(
            "GET", f"/rules/lists/bulk_operations/{operation_id}"
        )
        return response.get("result", {})

    def wait_for_operation(
        self, operation_id: str, timeout: int = 300, poll_interval: int = 2
    ) -> dict:
        """Block until a bulk operation completes.

        Raises:
            CloudflareAPIError: If the operation fails or times out.
        """
        start_time = time.monotonic()

        while True:
            status = self.get_bulk_operation(operation_id)
            state = status.get("status")

            if state == "completed":
                return status
            if state == "failed":
                raise CloudflareAPIError(
                    f"Bulk operation failed: {status.get('error')}"
                )

            if time.monotonic() - start_time > timeout:
                raise CloudflareAPIError(f"Bulk operation timed out after {timeout}s")

            time.sleep(poll_interval)
