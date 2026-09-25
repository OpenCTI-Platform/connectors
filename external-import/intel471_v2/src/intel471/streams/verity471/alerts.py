import datetime
from typing import Any, Union

from .base import Verity471Stream

# Safety margin, in milliseconds, applied when the request filters change and the
# stored cursor has to be discarded. The from-date is moved back to the event-time
# high-water mark we had reached minus this margin, never forward of it, so a small
# window is re-ingested rather than skipped. It covers any lag between the order the
# stream returns alerts in and their `creation_ts`. Mirrors the Sentinel playbook's
# `MigrationMarginHours` default of 1 hour.
ALERTS_MIGRATION_MARGIN_MS = 60 * 60 * 1000


class Verity471AlertsStream(Verity471Stream):
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

    # Highest `creation_ts` (epoch ms) processed so far this run; seeded from state at
    # the start of every run and persisted alongside the cursor. Used to re-anchor the
    # from-date on a filter change without decoding the cursor.
    _lastseen_ms = 0

    @property
    def _lastseen_key(self) -> str:
        return f"{self.label}_lastseen_v471"

    @property
    def _filters_state_key(self) -> str:
        return f"{self.label}_filters_v471"

    @property
    def _initdate_key(self) -> str:
        return f"{self.label}_initdate_v471"

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

    @staticmethod
    def _to_ms(value: Any) -> Union[int, None]:
        """Normalise a `creation_ts` (a `datetime`, or already epoch ms) to epoch ms."""
        if isinstance(value, datetime.datetime):
            aware = value if value.tzinfo else value.replace(tzinfo=datetime.UTC)
            return int(aware.timestamp() * 1000)
        if isinstance(value, (int, float)):
            return int(value)
        return None

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = super()._get_api_kwargs(cursor)
        config = self.connector_config
        if config is None:
            return kwargs
        if config.watcher_group_ids:
            kwargs["watcher_group_ids"] = ",".join(config.watcher_group_ids)
        if config.watcher_ids:
            kwargs["watcher_ids"] = ",".join(config.watcher_ids)
        if config.statuses:
            kwargs["statuses"] = ",".join(config.statuses)
        if config.is_trashed_included:
            kwargs["is_trashed_included"] = config.is_trashed_included
        return kwargs

    def _get_cursor(self) -> Union[str, None]:
        cursor = super()._get_cursor()
        self._lastseen_ms = self._get_state(self._lastseen_key) or 0
        current = self._filters_fingerprint()
        stored = self._get_state(self._filters_state_key)
        if stored is None or stored == current:
            if stored is None:
                self._set_state(self._filters_state_key, current)
            return cursor
        # Filters changed: the stored cursor is no longer valid. Discard it and
        # re-anchor the from-date to where we had actually reached minus the margin.
        self.helper.log_warning(
            f"{self.__class__.__name__} detected changed alert filters; discarding the "
            f"cursor and re-anchoring the from-date. Expect a small overlapping "
            f"re-ingest. A change that widens the filters backfills only the margin."
        )
        anchor_ms = self._lastseen_ms or int(
            datetime.datetime.now(datetime.UTC).timestamp() * 1000
        )
        current_initdate = self._get_state(self._initdate_key) or self.initial_history
        self._set_state(
            self._initdate_key,
            max(current_initdate, anchor_ms - ALERTS_MIGRATION_MARGIN_MS),
        )
        self._update_cursor(None)
        self._set_state(self._filters_state_key, current)
        return None

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        page = getattr(api_response, self.api_payload_objects_key, None) or []
        stamps = [
            ms
            for alert in page
            if (ms := self._to_ms(getattr(alert, "creation_ts", None))) is not None
        ]
        if stamps:
            self._lastseen_ms = max(self._lastseen_ms, *stamps)
        return super()._get_cursor_value(api_response)

    def _update_cursor(self, value: str) -> None:
        super()._update_cursor(value)
        if self._lastseen_ms:
            self._set_state(self._lastseen_key, self._lastseen_ms)
