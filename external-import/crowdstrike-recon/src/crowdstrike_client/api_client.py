from falconpy import Recon as CrowdstrikeRecon
from pycti import OpenCTIConnectorHelper
from pydantic import HttpUrl


class CrowdstrikeReconClient:

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        base_url: HttpUrl,
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
            base_url (HttpUrl): CrowdStrike Falcon API base URL.
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
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.filter_topic = filter_topic
        self.filter_type = filter_type
        self.filter_priority = filter_priority

        self.cs = CrowdstrikeRecon(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )

    def _build_fql_filter(self, from_date) -> str:
        """
        Build an FQL filter string from the configured filter parameters.
        Each parameter is a comma-separated string (e.g. "high,medium").
        Multiple values for the same field are combined with commas (OR logic).
        Different fields are combined with '+' (AND logic).

        :return: FQL filter string or None if no filters are set.
        """
        fql_parts = []

        topic_values = [v.strip() for v in self.filter_topic.split(",") if v.strip()] if self.filter_topic else []
        type_values = [v.strip() for v in self.filter_type.split(",") if v.strip()] if self.filter_type else []
        priority_values = [v.strip() for v in self.filter_priority.split(",") if v.strip()] if self.filter_priority else []

        if topic_values:
            values = ",".join(f"'{v}'" for v in topic_values)
            fql_parts.append(f"topic:[{values}]")

        if type_values:
            values = ",".join(f"'{v}'" for v in type_values)
            fql_parts.append(f"item_type:[{values}]")

        if priority_values:
            values = ",".join(f"'{v}'" for v in priority_values)
            fql_parts.append(f"priority:[{values}]")

        # filter per updated_date
        fql_parts.append(f"created_date:>'{from_date}'")

        return "+".join(fql_parts)

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
                {"filter": fql_filter},
            )

        while True:
            kwargs = {
                "limit": limit,
                "offset": offset,
                "sort": sort,
            }
            if fql_filter:
                kwargs["filter"] = fql_filter

            result = self.cs.query_notifications(**kwargs)

            resources = result.get("body", {}).get("resources", [])
            if not resources:
                break

            notification_ids.extend(resources)

            total = result.get("body", {}).get("meta", {}).get("pagination", {}).get("total", 0)
            if len(notification_ids) >= total:
                break

            offset += limit

        return notification_ids


    def get_notification_detail(self, notification_id) -> dict:
        """
        :param notification_id:
        :return:
        """
        notification = self.cs.get_notifications_detailed(ids=notification_id)
        return notification.get("body").get("resources")[0]
