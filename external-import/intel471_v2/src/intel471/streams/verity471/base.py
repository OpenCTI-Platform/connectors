import datetime
from typing import Any, ClassVar, Union

from ..core.base import Intel471Stream

# Safety margin, in milliseconds, applied when a stream's request filters change and the
# stored cursor has to be discarded. The from-date is moved back to the event-time
# high-water mark the stream had reached minus this margin, never forward of it, so a
# small window is re-ingested rather than skipped. It covers any lag between the order
# the stream returns items in and their event timestamp. Mirrors the Sentinel playbook's
# `MigrationMarginHours` default of 1 hour.
FILTER_MIGRATION_MARGIN_MS = 60 * 60 * 1000


class Verity471Stream(Intel471Stream):
    """
    All search endpoints in Verity471 are of 'stream' type.
    """

    size: ClassVar[int]

    @property
    def cursor_name(self) -> str:
        return f"{self.label}_cursor_v471"

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        return api_response.cursor_next

    def _get_initial_history(self):
        # initial history timestamp is saved in OpenCTI instance state
        # to avoid cursor/from mismatch if the timestamp is changed in the config
        # but the cursor is not reset.
        return self._get_stored_initial_history(f"{self.label}_initdate_v471")

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = {"var_from": self._get_initial_history(), "size": type(self).size}
        if cursor:
            kwargs["cursor"] = cursor
        return kwargs

    def _get_offsets(self) -> list[Union[None, int]]:
        return [None]


class FilterAwareVerity471Stream(Verity471Stream):
    """
    A Verity471 stream whose API call takes filter query parameters taken from the
    connector config.

    A Verity471 cursor is only valid for the exact filter set it was issued against, so
    when any of the filters change the stored cursor is discarded and the from-date is
    re-anchored to the event-time high-water mark the stream had reached (tracked
    independently of the opaque cursor) minus a safety margin. Expect a small
    overlapping re-ingest on a filter change; widening a filter backfills only the
    margin.

    Subclasses provide the filter set through `_filters_fingerprint` (a stable string
    identifying the current filters) and `_filter_kwargs` (the query parameters to add),
    and name the per-item event timestamp attribute in `_timestamp_field`.
    """

    # Name of the attribute on each API item holding its event timestamp. It may be a
    # `datetime`, epoch milliseconds, or a string (epoch-ms or ISO-8601); `_to_ms`
    # normalizes all three. Used to re-anchor the from-date on a filter change.
    _timestamp_field: ClassVar[str]
    # Milliseconds the from-date is moved back by when re-anchoring after a filter
    # change. See `FILTER_MIGRATION_MARGIN_MS`.
    migration_margin_ms: ClassVar[int] = FILTER_MIGRATION_MARGIN_MS

    # Highest event timestamp (epoch ms) processed so far this run; seeded from state at
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
        """Return a stable string identifying the current filter set (override)."""
        return ""

    def _filter_kwargs(self) -> dict:
        """Return the filter query parameters for the API call (override)."""
        return {}

    @staticmethod
    def _to_ms(value: Any) -> Union[int, None]:
        """
        Normalize an event timestamp to epoch milliseconds.

        Accepts a `datetime`, already-epoch milliseconds, or a string holding either
        epoch milliseconds or an ISO-8601 timestamp. Anything else (including an
        unparsable string) returns `None`.
        """
        if isinstance(value, datetime.datetime):
            aware = value if value.tzinfo else value.replace(tzinfo=datetime.UTC)
            return int(aware.timestamp() * 1000)
        if isinstance(value, bool):  # bool is an int subclass; never a timestamp
            return None
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            text = value.strip()
            if text.isdigit():
                return int(text)
            try:
                parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
            aware = parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.UTC)
            return int(aware.timestamp() * 1000)
        return None

    def _get_api_kwargs(self, cursor: Union[None, str]) -> dict:
        kwargs = super()._get_api_kwargs(cursor)
        kwargs.update(self._filter_kwargs())
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
            f"{self.__class__.__name__} detected changed filters; discarding the "
            f"cursor and re-anchoring the from-date. Expect a small overlapping "
            f"re-ingest. A change that widens the filters backfills only the margin."
        )
        current_initdate = self._get_state(self._initdate_key) or self.initial_history
        # Without a cursor nothing was ever ingested (e.g. the first request failed),
        # so keep the original from-date. With a cursor but no last-seen timestamp we
        # cannot tell how far we got, so fall back to now.
        anchor_ms = self._lastseen_ms or current_initdate
        if not self._lastseen_ms and cursor:
            anchor_ms = int(datetime.datetime.now(datetime.UTC).timestamp() * 1000)
        self._set_state(
            self._initdate_key,
            max(current_initdate, anchor_ms - self.migration_margin_ms),
        )
        self._update_cursor(None)
        self._set_state(self._filters_state_key, current)
        return None

    def _get_cursor_value(self, api_response: Any) -> Union[None, str, int]:
        page = getattr(api_response, self.api_payload_objects_key, None) or []
        stamps = [
            ms
            for item in page
            if (ms := self._to_ms(getattr(item, self._timestamp_field, None)))
            is not None
        ]
        if stamps:
            self._lastseen_ms = max(self._lastseen_ms, *stamps)
        return super()._get_cursor_value(api_response)

    def _update_cursor(self, value: str) -> None:
        super()._update_cursor(value)
        if self._lastseen_ms:
            self._set_state(self._lastseen_key, self._lastseen_ms)
