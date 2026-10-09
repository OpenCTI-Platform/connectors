"""CrowdStrike Falcon Alerts API v2 client.

The connector uses falconpy, the official CrowdStrike SDK, instead of the
connectors-sdk ``BaseClientApi``: falconpy handles the OAuth2 client-credentials
flow, token refresh and cloud regions.

Pagination: the Alerts API rejects queries where ``offset + limit`` exceeds
10 000, so alerts are paginated by keyset on ``updated_timestamp`` (ascending),
restarting at offset 0 from the last seen timestamp after every page.

An alert can be updated between the ID query and the detail call: its
``updated_timestamp`` then jumps forward and must not move the cursor, or the
alerts between the two timestamps would be skipped. The cursor only advances
to timestamps older than the query time minus ``CLOCK_SKEW_MARGIN``; more
recent alerts are still yielded and fetched again on the next query.
"""

from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from falconpy import Alerts

USER_AGENT = "OpenCTI-CrowdStrike-Incidents-Connector"
# Server-side limit on offset + limit for GET /alerts/queries/alerts/v2.
MAX_WINDOW = 10_000
SORT = "updated_timestamp|asc"
# Tolerated clock difference between the connector host and CrowdStrike.
CLOCK_SKEW_MARGIN = timedelta(minutes=5)


def timestamp_sort_key(timestamp: str) -> str:
    """Return a sortable form of an API timestamp.

    The API returns a variable number of fractional digits
    (``...:56.5897592Z``, ``...:46.571156996Z``), which does not sort correctly
    as plain text. The fraction is right-padded to nanoseconds.
    """
    base, _, fraction = timestamp.rstrip("Z").partition(".")
    return f"{base}.{fraction.ljust(9, '0')}"


def format_timestamp(value: datetime) -> str:
    """Format a datetime as an FQL timestamp (UTC, second precision)."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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

    DEFAULT_PAGE_SIZE = 1000

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        page_size: int = DEFAULT_PAGE_SIZE,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._alerts = Alerts(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            user_agent=USER_AGENT,
        )
        self._page_size = page_size
        self._now = now

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
            include_hidden: Whether to include alerts hidden in the console.
            skip_ids: Composite IDs already processed at the ``since`` timestamp.

        Yields:
            ``AlertPage`` objects, each with the cursor to checkpoint after it.
        """
        product_filter = ",".join(f"'{product}'" for product in products)
        cursor = since
        offset = 0
        boundary_ids: set[str] = set(skip_ids)

        while True:
            if offset + self._page_size > MAX_WINDOW:
                raise CrowdstrikeApiError(
                    None,
                    f"More than {MAX_WINDOW} alerts share the same updated_timestamp "
                    f"({cursor}); cannot paginate further. Restart the connector "
                    "from a later point by resetting its state.",
                )
            stable_limit = timestamp_sort_key(
                format_timestamp(self._now() - CLOCK_SKEW_MARGIN)
            )
            ids = self._query_ids(
                fql=f"product:[{product_filter}]+updated_timestamp:>='{cursor}'",
                offset=offset,
                include_hidden=include_hidden,
            )
            new_ids = [i for i in ids if i not in boundary_ids]
            alerts = self._get_alerts(new_ids, include_hidden) if new_ids else []
            alerts.sort(
                key=lambda alert: timestamp_sort_key(alert["updated_timestamp"])
            )
            # Only alerts older than the query time can move the cursor: a more
            # recent timestamp may come from an update made after the query.
            stable = [
                alert
                for alert in alerts
                if timestamp_sort_key(alert["updated_timestamp"]) <= stable_limit
            ]
            next_cursor = stable[-1]["updated_timestamp"] if stable else cursor

            if timestamp_sort_key(next_cursor) == timestamp_sort_key(cursor):
                # Keyset cannot move forward (every alert shares the cursor
                # timestamp or is too recent): page by offset instead.
                offset += self._page_size
            else:
                cursor = next_cursor
                offset = 0
                boundary_ids = set()
            boundary_ids.update(
                alert["composite_id"]
                for alert in stable
                if timestamp_sort_key(alert["updated_timestamp"])
                == timestamp_sort_key(cursor)
            )

            if alerts:
                yield AlertPage(alerts, cursor, frozenset(boundary_ids))
            if len(ids) < self._page_size:
                return

    def _query_ids(self, fql: str, offset: int, include_hidden: bool) -> list[str]:
        response = self._alerts.query_alerts_v2(
            filter=fql,
            sort=SORT,
            limit=self._page_size,
            offset=offset,
            include_hidden=include_hidden,
        )
        return self._resources(response)

    def _get_alerts(
        self, composite_ids: list[str], include_hidden: bool
    ) -> list[dict[str, Any]]:
        response = self._alerts.get_alerts_v2(
            composite_ids=composite_ids, include_hidden=include_hidden
        )
        return self._resources(response)

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
