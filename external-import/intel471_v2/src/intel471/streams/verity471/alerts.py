from .base import FILTER_MIGRATION_MARGIN_MS, FilterAwareVerity471Stream

# Kept as a module-level name for backwards compatibility (it is the alerts stream's
# re-anchor margin and is referenced by tests). Mirrors the Sentinel playbook's
# `MigrationMarginHours` default of 1 hour.
ALERTS_MIGRATION_MARGIN_MS = FILTER_MIGRATION_MARGIN_MS


class Verity471AlertsStream(FilterAwareVerity471Stream):
    """
    Watcher alerts stream (`/watchers/v1/alerts/stream`).

    Unlike the other Verity471 streams it exposes filter query parameters
    (`watcher_group_ids`, `watcher_ids`, `statuses`, `is_trashed_included`) taken from
    the connector config. A Verity471 cursor is only valid for the exact filter set it
    was issued against, so when any of these filters change the stored cursor is
    discarded and the from-date is re-anchored to the event-time high-water mark we had
    reached (tracked independently of the opaque cursor) minus a safety margin.
    """

    label = "alerts"
    group_label = "alerts"
    api_payload_objects_key = "alerts"
    api_class_name = "AlertsApi"
    api_method_name = "get_alerts_stream"
    size = 100
    _timestamp_field = "creation_ts"

    def _filters_fingerprint(self) -> str:
        config = self.connector_config
        if config is None:
            return ""
        return "|".join(
            [
                ",".join(sorted(config.watcher_group_ids or [])),
                ",".join(sorted(config.watcher_ids or [])),
                ",".join(sorted(config.statuses or [])),
                str(bool(config.is_trashed_included)),
            ]
        )

    def _filter_kwargs(self) -> dict:
        config = self.connector_config
        if config is None:
            return {}
        kwargs = {}
        if config.watcher_group_ids:
            kwargs["watcher_group_ids"] = ",".join(config.watcher_group_ids)
        if config.watcher_ids:
            kwargs["watcher_ids"] = ",".join(config.watcher_ids)
        if config.statuses:
            kwargs["statuses"] = ",".join(config.statuses)
        if config.is_trashed_included:
            kwargs["is_trashed_included"] = config.is_trashed_included
        return kwargs
