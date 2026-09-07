"""ZeroFox Alerts API client using the SDK BaseClientApi."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from connectors_sdk import BaseClientApi


class ZerofoxAlertsClient(BaseClientApi):
    """HTTP client for the ZeroFox Alerts API.

    Uses Personal Access Token (PAT) authentication:
        Authorization: Token <PAT>

    Reference:
        https://api.zerofox.com/1.0/docs/#operation--alerts--get
    """

    def __init__(self, base_url: str, api_token: str, **kwargs: Any) -> None:
        super().__init__(base_url, **kwargs)
        self._api_token = api_token

    @property
    def session_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self._api_token}",
            "zf-source": "OpenCTI",
        }

    def get_alerts(
        self,
        *,
        min_timestamp: str | None = None,
        status: list[str] | None = None,
        page_size: int = 100,
        sort_field: str = "timestamp",
        sort_direction: str = "asc",
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Paginate through ZeroFox alerts using cursor-based pagination.

        Args:
            min_timestamp: ISO 8601 minimum timestamp filter.
            status: List of alert statuses to filter (e.g. ['open', 'escalated']).
            page_size: Number of results per page.
            sort_field: Field to sort by.
            sort_direction: Sort direction ('asc' or 'desc').

        Yields:
            Lists of alert dicts, one per page.
        """
        params: dict[str, Any] = {
            "limit": page_size,
            "sort_field": sort_field,
            "sort_direction": sort_direction,
        }
        if min_timestamp:
            params["min_timestamp"] = min_timestamp
        if status:
            params["status"] = ",".join(status)

        yield from self._paginate_cursor(
            "/1.0/alerts/",
            params=params,
            results_key="alerts",
            next_key="next",
        )

    def _paginate_cursor(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        results_key: str,
        next_key: str = "next",
    ) -> Generator[list[dict[str, Any]], None, None]:
        """Generic cursor-based pagination.

        Args:
            path: Initial API path.
            params: Query parameters for the first request.
            results_key: Key in the response containing the results list.
            next_key: Key in the response containing the next page URL.

        Yields:
            Lists of result dicts, one per page.
        """
        next_url: str | None = path

        while next_url:
            if next_url.startswith("http"):
                response = self._get(next_url.replace(self._base_url, ""))
            else:
                response = self._get(next_url, params=params)

            results = response.get(results_key, [])
            if not results:
                break

            yield results
            next_url = response.get(next_key)

    def get_alert_by_id(self, alert_id: int) -> dict[str, Any]:
        """Retrieve a single alert by ID.

        Args:
            alert_id: The ZeroFox alert ID.

        Returns:
            Alert dict.
        """
        return self._get(f"/1.0/alerts/{alert_id}/")
