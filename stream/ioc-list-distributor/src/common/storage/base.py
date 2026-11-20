"""The storage interface: what the connector, the exporter and the feed distributor need
from the IOC database. They only ever call these methods, never SQL.

The database implementation lives in storage/<db>_store.py, and storage/__init__.py
opens it (open_store()) with its settings.

Data model (one row per IOC value of an indicator):
  indicator_id        OpenCTI internal id (stable across pattern edits)
  stix_id             STIX standard id, for traceability and as a delete fallback
  ioc_type            ip | domain | url | hash
  sub_type            ipv4 / ipv6 / domain / url / md5 / sha1 / sha256 / sha512
  value               the IOC value
  name, score, valid_until, created, modified   copied from the indicator
  first_seen_local    first time this connector stored the value
  last_updated_local  last create/update event received for it
  key (indicator_id, ioc_type, value) is unique.
Timestamps are fixed-width UTC strings (see timeutil), so ordering them as text is ordering in time.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

# The dates the export window and sort can use (EXPORT_BASE_ATTRIBUTE).
BASE_ATTRIBUTES = ("created", "modified", "first_seen_local", "last_updated_local")


class IocStore(ABC):
    """IOC database. One writer (the connector) and readers (the feed distributor)
    may use it at the same time, from separate processes; methods are thread-safe."""

    backend_name = "abstract"

    # ------------------------------------------------------------------ writes
    @abstractmethod
    def upsert_indicator(
        self,
        indicator_id: str,
        stix_id: str | None,
        iocs: list[tuple[str, str, str]],
        *,
        name: str | None,
        score: int | None,
        valid_until: str | None,
        created: str | None,
        modified: str | None,
    ) -> tuple[int, int, int]:
        """Replace the IOC values held for one indicator, atomically.

        iocs: list of (ioc_type, sub_type, value). Values the indicator no longer carries
        are removed; first_seen_local is kept for values already stored.
        Returns (added, updated, removed).
        """

    @abstractmethod
    def delete_indicator(self, indicator_id: str, stix_id: str | None = None) -> int:
        """Remove every value of an indicator, matched on indicator_id or, as a fallback,
        stix_id. Returns the number of rows removed."""

    @abstractmethod
    def purge_older_than(self, cutoff_iso: str) -> int:
        """Remove rows whose COALESCE(modified, last_updated_local) is older than the cutoff.
        Returns the number of rows removed (used only when DB_RETENTION_DAYS > 0)."""

    @abstractmethod
    def record_event(self, event_type: str, skipped: bool) -> None:
        """Stream bookkeeping in the meta table: stream_last_event_at, stream_last_event_type,
        stream_events_total (+1) and, when skipped, stream_indicators_skipped_total (+1).
        """

    # ------------------------------------------------------------------- reads
    @abstractmethod
    def select_for_export(
        self,
        ioc_type: str,
        base_attribute: str,
        cutoff: str | None,
        expiry_now: str | None,
        sort_order: str,
    ) -> list[tuple[str, str]]:
        """Distinct values of one type, as (value, sub_type).

        base_attribute: one of BASE_ATTRIBUTES, the date the window and the sort use.
        cutoff: window start (ISO) or None for no window; keeps rows with base_attribute >= cutoff.
        expiry_now: current time (ISO) to drop rows whose valid_until is not after it, or None.
        sort_order: 'base_attribute' -> newest first; 'score' -> highest score first, then newest.
        A value held by several indicators is returned once (max sub_type, score and date).
        """

    def export_date_of(  # pylint: disable=unused-argument
        self, ioc_type: str, base_attribute: str, value: str | None
    ) -> str | None:
        """The base_attribute date select_for_export sorted this value by (max over its rows).

        Optional: used only for the cap report in /stats and the log. Backends that do not
        implement it return None and the report says 'unknown'.
        """
        return None

    def export_score_of(  # pylint: disable=unused-argument
        self,
        ioc_type: str,
        base_attribute: str,
        cutoff: str | None,
        expiry_now: str | None,
        value: str | None,
    ) -> int | None:
        """The score select_for_export sorted this value by in score order: the highest score
        of its rows inside the same window and expiry filter (no score counts as 0).

        Optional: used only for the cap report in /stats and the log when EXPORT_SORT_ORDER=score.
        Backends that do not implement it return None and the report says 'unknown'.
        """
        return None

    @abstractmethod
    def counts_by_type(self) -> dict[str, int]:
        """Distinct values per ioc_type."""

    @abstractmethod
    def count_indicators(self) -> int:
        """Distinct indicator_id values."""

    @abstractmethod
    def get_all_meta(self) -> dict[str, str]:
        """Every key/value of the meta table."""

    # --------------------------------------------------------------- lifecycle
    def close(self) -> None:  # optional for backends without connections to release
        """Release connections."""

    def describe(self) -> str:
        """Where the data lives, for the startup log (no secrets)."""
        return self.backend_name

    @staticmethod
    def check_base_attribute(base_attribute: str) -> str:
        """Backends that put the attribute in SQL must call this (it is a column name)."""
        if base_attribute not in BASE_ATTRIBUTES:
            raise ValueError(f"Unsupported base attribute {base_attribute!r}")
        return base_attribute
