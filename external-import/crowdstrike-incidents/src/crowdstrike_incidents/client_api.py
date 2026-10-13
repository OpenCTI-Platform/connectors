"""CrowdStrike Falcon Alerts API client.

The connector uses falconpy, the official CrowdStrike SDK, instead of the
connectors-sdk ``BaseClientApi``: falconpy handles the OAuth2 client-credentials
flow, token refresh and cloud regions.

Alerts are retrieved with ``POST /alerts/combined/alerts/v1``, which returns
complete alerts in a single call per page.

Pagination: the endpoint paginates "on live data", and records may appear on
several pages or on none when sorting on a field that changes over time, such
as ``updated_timestamp``. Pages are therefore chained by keyset rather than by
``after`` token: each page restarts from the last ``updated_timestamp`` seen,
which can never skip an alert. The ``after`` token is only used to page through
alerts sharing that exact timestamp.
"""

from collections.abc import Generator, Iterable
from dataclasses import dataclass, field
from typing import Any

from falconpy import Alerts

USER_AGENT = "OpenCTI-CrowdStrike-Incidents-Connector"
SORT = "updated_timestamp|asc"
# Maximum page size of POST /alerts/combined/alerts/v1.
MAX_PAGE_SIZE = 1000


def timestamp_sort_key(timestamp: str) -> str:
    """Return a sortable form of an API timestamp.

    The API returns a variable number of fractional digits
    (``...:56.5897592Z``, ``...:46.571156996Z``), which does not sort correctly
    as plain text. The fraction is right-padded to nanoseconds.
    """
    base, _, fraction = timestamp.rstrip("Z").partition(".")
    return f"{base}.{fraction.ljust(9, '0')}"


@dataclass(frozen=True)
class AlertPage:
    """A page of raw alerts and the position to resume from after it.

    Attributes:
        alerts: Raw alert dicts, sorted by ``updated_timestamp`` ascending.
        cursor: ``updated_timestamp`` to resume from once the page is processed.
        boundary_ids: Composite IDs already yielded whose timestamp equals the
            cursor; the inclusive filter returns them again and they are skipped.
    """

    alerts: list[dict[str, Any]]
    cursor: str
    boundary_ids: frozenset[str] = field(default_factory=frozenset)


class CrowdstrikeApiError(Exception):
    """Raised when the CrowdStrike API returns a non-success status."""

    def __init__(self, status_code: int | None, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


class CrowdstrikeAlertsClient:
    """Thin wrapper around falconpy ``Alerts`` for incremental collection."""

    DEFAULT_PAGE_SIZE = MAX_PAGE_SIZE

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        self._alerts = Alerts(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            user_agent=USER_AGENT,
        )
        self._page_size = page_size

    def iter_alert_pages(
        self,
        since: str,
        products: list[str],
        include_hidden: bool = False,
        skip_ids: Iterable[str] = (),
    ) -> Generator[AlertPage, None, None]:
        """Yield pages of raw alerts updated at or after ``since``, oldest first.

        Args:
            since: ISO 8601 timestamp; alerts with ``updated_timestamp >= since``
                are returned.
            products: Alert products to filter on (FQL ``product`` field).
            include_hidden: Whether to include the alerts hidden in the console
                (``show_in_ui:false``).
            skip_ids: Composite IDs already processed at the ``since`` timestamp.

        Yields:
            ``AlertPage`` objects, each with the cursor to checkpoint after it.
        """
        product_filter = ",".join(f"'{product}'" for product in products)
        hidden_filter = "" if include_hidden else "+show_in_ui:true"
        cursor = since
        after: str | None = None
        boundary_ids: set[str] = set(skip_ids)
        has_more = True

        while has_more:
            alerts, next_after = self._get_page(
                fql=(
                    f"product:[{product_filter}]"
                    f"+updated_timestamp:>='{cursor}'{hidden_filter}"
                ),
                after=after,
            )
            alerts.sort(
                key=lambda alert: timestamp_sort_key(alert["updated_timestamp"])
            )
            new_alerts = [a for a in alerts if a["composite_id"] not in boundary_ids]

            last_timestamp = alerts[-1]["updated_timestamp"] if alerts else cursor
            if timestamp_sort_key(last_timestamp) == timestamp_sort_key(cursor):
                # The whole page shares the cursor timestamp: keyset cannot move
                # forward, page through that timestamp with the after token.
                after = next_after
            else:
                cursor = last_timestamp
                after = None
                boundary_ids = set()
            boundary_ids.update(
                alert["composite_id"]
                for alert in alerts
                if timestamp_sort_key(alert["updated_timestamp"])
                == timestamp_sort_key(cursor)
            )

            if new_alerts:
                yield AlertPage(new_alerts, cursor, frozenset(boundary_ids))
            # The API returns an after token only when more results are available
            has_more = next_after is not None and bool(alerts)

    def _get_page(
        self, fql: str, after: str | None
    ) -> tuple[list[dict[str, Any]], str | None]:
        body: dict[str, Any] = {"filter": fql, "sort": SORT, "limit": self._page_size}
        if after:
            body["after"] = after
        response = self._alerts.get_alerts_combined(body=body)
        resources = self._resources(response)
        pagination = (response.get("body") or {}).get("meta", {}).get("pagination", {})
        return resources, pagination.get("after") or None

    @staticmethod
    def _resources(response: dict[str, Any]) -> list[Any]:
        status_code = response.get("status_code")
        body = response.get("body") or {}
        if status_code != 200:
            errors = "; ".join(
                str(error.get("message")) for error in body.get("errors") or []
            )
            message = f"CrowdStrike API error (HTTP {status_code}): {errors}"
            if status_code == 403:
                message += " - check that the API client has the 'Alerts: Read' scope."
            raise CrowdstrikeApiError(status_code, message)
        return body.get("resources") or []
