from falconpy import Recon as CrowdstrikeRecon
from pycti import OpenCTIConnectorHelper


class CrowdstrikeReconClient:

    # CrowdStrike's get_notifications_detailed accepts a batch of IDs, so detail
    # lookups are chunked to avoid one HTTP request per notification.
    _DETAIL_CHUNK_SIZE = 100
    # Safety guard so a misbehaving API (e.g. a missing/zero ``total``) cannot
    # turn pagination into an unbounded loop.
    _MAX_PAGES = 1000

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: str,
        client_id: str,
        client_secret: str,
        filter_topic: str = "",
        filter_type: str = "",
        filter_priority: str = "",
    ):
        """
        Initialize the CrowdStrike Recon API client.

        Args:
            helper (OpenCTIConnectorHelper): Connector helper used for logging.
            base_url (str): CrowdStrike Falcon API base URL.
            client_id (str): CrowdStrike Falcon API client ID.
            client_secret (str): CrowdStrike Falcon API client secret.
            filter_topic (str): Comma-separated topic name(s) used to filter
                notifications. An empty string disables topic filtering.
            filter_type (str): Comma-separated type(s) used to filter
                notifications. An empty string disables type filtering.
            filter_priority (str): Comma-separated priority value(s) used to
                filter notifications. An empty string disables priority
                filtering.
        """
        self.helper = helper
        self.filter_topic = filter_topic
        self.filter_type = filter_type
        self.filter_priority = filter_priority

        # The client secret is only needed to build the falconpy client; it is
        # intentionally not kept as an instance attribute to limit the secret's
        # exposure surface (logs, reprs, debuggers).
        self.cs = CrowdstrikeRecon(
            client_id=client_id, client_secret=client_secret, base_url=base_url
        )

    @staticmethod
    def _escape_fql_value(value: str) -> str:
        """
        Escape single quotes so a filter value cannot break out of (or inject
        into) the single-quoted FQL string.
        """
        return value.replace("'", "\\'")

    def _build_fql_filter(self, from_date) -> str:
        """
        Build an FQL filter string from the configured filter parameters.
        Each parameter is a comma-separated string (e.g. "high,medium").
        Multiple values for the same field are combined with commas (OR logic).
        Different fields are combined with '+' (AND logic).

        :return: FQL filter string.
        """
        fql_parts = []

        for field_name, raw_value in (
            ("topic", self.filter_topic),
            ("item_type", self.filter_type),
            ("priority", self.filter_priority),
        ):
            values = (
                [v.strip() for v in raw_value.split(",") if v.strip()]
                if raw_value
                else []
            )
            if values:
                joined = ",".join(f"'{self._escape_fql_value(v)}'" for v in values)
                fql_parts.append(f"{field_name}:[{joined}]")

        # Only fetch notifications created strictly after the last processed date
        fql_parts.append(f"created_date:>'{from_date}'")

        return "+".join(fql_parts)

    def _raise_for_status(self, result: dict, operation: str) -> None:
        """
        Raise on a non-2xx falconpy response so auth / permission / rate-limit
        failures are surfaced instead of being silently treated as "no data".
        """
        result = result or {}
        status_code = result.get("status_code")
        if status_code is None or status_code >= 300:
            errors = (result.get("body") or {}).get("errors")
            self.helper.connector_logger.error(
                "[API CLIENT] CrowdStrike Recon API request failed",
                meta={
                    "operation": operation,
                    "status_code": status_code,
                    "errors": errors,
                },
            )
            raise RuntimeError(
                f"CrowdStrike Recon API '{operation}' failed with status "
                f"{status_code}: {errors}"
            )

    def query_notifications(self, from_date) -> list[str]:
        """
        Query notification IDs from the CrowdStrike Recon API with optional FQL filters.
        Handles pagination to retrieve all matching notification IDs.

        :return: List of notification IDs.
        """
        notification_ids = []
        offset = 0
        limit = 100
        sort = "created_date|asc"

        fql_filter = self._build_fql_filter(from_date=from_date)

        if fql_filter:
            self.helper.connector_logger.info(
                "[API CLIENT] Querying notifications with FQL filter",
                meta={"filter": fql_filter},
            )

        for _ in range(self._MAX_PAGES):
            kwargs = {
                "limit": limit,
                "offset": offset,
                "sort": sort,
            }
            if fql_filter:
                kwargs["filter"] = fql_filter

            result = self.cs.query_notifications(**kwargs)
            self._raise_for_status(result, "query_notifications")

            body = result.get("body") or {}
            resources = body.get("resources") or []
            if not resources:
                break

            notification_ids.extend(resources)

            # A short page (fewer than ``limit`` results) means there is no next
            # page. ``total`` is only used as an optimization when the API
            # actually reports it: a missing/zero ``total`` must not be treated
            # as "done", otherwise a full first page would truncate the results.
            if len(resources) < limit:
                break

            total = ((body.get("meta") or {}).get("pagination") or {}).get("total")
            if total and len(notification_ids) >= total:
                break

            offset += limit
        else:
            self.helper.connector_logger.warning(
                "[API CLIENT] Reached pagination safety limit while querying "
                "notifications; results may be truncated",
                meta={"max_pages": self._MAX_PAGES},
            )

        return notification_ids

    def get_notifications_details(self, notification_ids: list[str]) -> list[dict]:
        """
        Fetch full notification details for a list of notification IDs.

        IDs are sent in batches (``_DETAIL_CHUNK_SIZE`` per request) because
        CrowdStrike's ``get_notifications_detailed`` accepts a list of IDs, which
        avoids one HTTP request per notification (N+1).

        :param notification_ids: Notification IDs to fetch details for.
        :return: List of notification detail dicts.
        """
        details: list[dict] = []
        for start in range(0, len(notification_ids), self._DETAIL_CHUNK_SIZE):
            chunk = notification_ids[start : start + self._DETAIL_CHUNK_SIZE]
            result = self.cs.get_notifications_detailed(ids=chunk)
            self._raise_for_status(result, "get_notifications_detailed")
            resources = (result.get("body") or {}).get("resources") or []
            details.extend(resources)
        return details
