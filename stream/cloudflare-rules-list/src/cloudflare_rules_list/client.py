"""Cloudflare Rules Lists API client.

Documentation:
https://developers.cloudflare.com/api/resources/rules/subresources/lists/
"""

import json
import time
from collections.abc import Iterator
from typing import Any, Optional, Union

import requests
from pydantic import HttpUrl


class CloudflareAPIError(Exception):
    """Exception raised for Cloudflare API errors.

    Attributes:
        status_code: The HTTP status of the Cloudflare response, None when
            Cloudflare could not be reached.
    """

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class CloudflareOperationError(CloudflareAPIError):
    """A bulk operation Cloudflare accepted but failed or did not complete in time.

    Attributes:
        timed_out: Whether the operation was still running at the deadline.
    """

    def __init__(self, message: str, timed_out: bool = False) -> None:
        super().__init__(message, status_code=200)
        self.timed_out = timed_out


def _result_object(payload: dict) -> dict:
    """Return the ``result`` object of a Cloudflare response.

    Raises:
        CloudflareAPIError: When ``result`` is missing, null or not an object, with
            a success status so that the shared "unexpected response" reason
            applies: a bulk change is never taken as done without its result.
    """
    result = payload.get("result")
    if not isinstance(result, dict):
        raise CloudflareAPIError(
            "Unexpected Cloudflare response: 'result' is missing or not an object",
            status_code=200,
        )
    return result


class CloudflareRulesListClient:
    """Client for the Cloudflare Rules Lists API."""

    BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(
        self,
        account_id: str,
        api_token: str,
        timeout: int = 60,
        base_url: Optional[Union[str, HttpUrl]] = None,
    ):
        """Initialize the client.

        Args:
            account_id: Cloudflare account ID.
            api_token: API token (Bearer auth).
            timeout: Default request timeout in seconds.
            base_url: Override the Cloudflare API base URL (for testing or a
                compatible gateway). Accepts a ``str`` or a pydantic ``HttpUrl``.
                Defaults to the public Cloudflare API.
        """
        self.account_id = account_id
        self.api_token = api_token
        self.timeout = timeout
        self.base_url = (str(base_url) if base_url else self.BASE_URL).rstrip("/")
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
            raise CloudflareAPIError(
                f"API request failed: {error_msg}",
                status_code=(
                    err_response.status_code if err_response is not None else None
                ),
            ) from exc

        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise CloudflareAPIError(
                f"Invalid JSON in Cloudflare response: {response.text[:200]}",
                status_code=response.status_code,
            ) from exc
        if not isinstance(payload, dict):
            raise CloudflareAPIError(
                "Unexpected Cloudflare response: the body is not a JSON object",
                status_code=response.status_code,
            )
        if payload.get("success") is False:
            raise CloudflareAPIError(
                f"API request failed: {payload.get('errors')}",
                status_code=response.status_code,
            )
        return payload

    def list_lists(self) -> list[dict]:
        """List all rules lists in the account."""
        response = self._make_request("GET", "/rules/lists")
        return response.get("result", [])

    def get_list(self, list_id: str) -> dict:
        """Get a specific list's metadata."""
        response = self._make_request("GET", f"/rules/lists/{list_id}")
        return _result_object(response)

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

    @staticmethod
    def _next_cursor(response: dict) -> Optional[str]:
        """Return the cursor of the next list items page, None after the last one.

        Raises:
            CloudflareAPIError: When the pagination metadata is missing or malformed
                (Cloudflare always returns ``result_info`` on list items pages), so that
                a read-back is never cut short.
        """
        result_info = response.get("result_info")
        if not isinstance(result_info, dict):
            raise CloudflareAPIError(
                "Unexpected list items response: 'result_info' is missing or not an object",
                status_code=200,
            )
        cursors = result_info.get("cursors")
        if cursors is None:
            return None
        if not isinstance(cursors, dict):
            raise CloudflareAPIError(
                "Unexpected list items response: 'cursors' is not an object",
                status_code=200,
            )
        after = cursors.get("after")
        if after is not None and not isinstance(after, str):
            raise CloudflareAPIError(
                "Unexpected list items response: the 'after' cursor is not a string",
                status_code=200,
            )
        return after or None

    def iter_list_items(self, list_id: str, max_pages: int = 10_000) -> Iterator[dict]:
        """Iterate over every item of a list (deployment reconciliation read-back).

        Raises:
            CloudflareAPIError: On any API error, an unexpected payload, a cursor
                repeating the previous one or when ``max_pages`` is reached: a
                partial listing is never returned silently.
        """
        cursor: Optional[str] = None
        for _ in range(max_pages):
            response = self.get_list_items(list_id, cursor)
            items = response.get("result") if isinstance(response, dict) else None
            if not isinstance(items, list):
                raise CloudflareAPIError(
                    "Unexpected list items response: 'result' is not a list"
                )
            if not all(isinstance(item, dict) for item in items):
                raise CloudflareAPIError(
                    "Unexpected list items response: an item is not an object"
                )
            yield from items
            next_cursor = self._next_cursor(response)
            if not next_cursor:
                return
            if next_cursor == cursor:
                raise CloudflareAPIError(
                    "Cloudflare returned the same list items cursor twice, "
                    "the read-back pagination is not honored"
                )
            cursor = next_cursor
        raise CloudflareAPIError(
            f"List items read-back stopped after {max_pages} pages"
        )

    def delete_list_items(self, list_id: str, item_ids: list[str]) -> dict:
        """Delete items of a list by item id.

        Returns:
            Operation result, including an ``operation_id`` for the async bulk job.
        """
        response = self._make_request(
            "DELETE",
            f"/rules/lists/{list_id}/items",
            data={"items": [{"id": item_id} for item_id in item_ids]},
        )
        return _result_object(response)

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
        return _result_object(response)

    def get_bulk_operation(self, operation_id: str) -> dict:
        """Get the status of a bulk operation."""
        response = self._make_request(
            "GET", f"/rules/lists/bulk_operations/{operation_id}"
        )
        return _result_object(response)

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
                raise CloudflareOperationError(
                    f"Bulk operation failed: {status.get('error')}"
                )

            if time.monotonic() - start_time > timeout:
                raise CloudflareOperationError(
                    f"Bulk operation timed out after {timeout}s", timed_out=True
                )

            time.sleep(poll_interval)
