"""Persistent connector state with day-level and offset checkpoints."""

from __future__ import annotations

from connectors_sdk import ExternalImportConnectorState
from pydantic import Field


class ConnectorState(ExternalImportConnectorState):
    """Persistent checkpoints for WhoisFreaks feeds.

    For threat feeds the stored date is the latest fully ingested snapshot
    date. For NRD feeds it is the next calendar day to process. Per-feed
    offsets track progress within a daily feed; the connector persists them
    at the end of its callback.
    """

    threat_feed_dates: dict[str, str] = Field(default_factory=dict)
    nrd_dates: dict[str, str] = Field(default_factory=dict)
    # feed_key -> next offset to request (record count from start of that day)
    threat_feed_offsets: dict[str, int] = Field(default_factory=dict)
    nrd_offsets: dict[str, int] = Field(default_factory=dict)
    threat_feed_offset_dates: dict[str, str] = Field(default_factory=dict)
    nrd_offset_dates: dict[str, str] = Field(default_factory=dict)

    def get_next_date(self, feed_type: str, default: str) -> str:
        """Return the next date to process for a threat feed."""
        return self.threat_feed_dates.get(feed_type, default)

    def set_next_date(self, feed_type: str, next_date: str) -> None:
        """Set the next date for a threat feed and clear its offset."""
        self.threat_feed_dates[feed_type] = next_date
        self.threat_feed_offsets.pop(feed_type, None)
        self.threat_feed_offset_dates.pop(feed_type, None)

    def get_threat_offset(self, feed_type: str) -> int:
        """Return the record offset for the current threat-feed day."""
        return int(self.threat_feed_offsets.get(feed_type, 0))

    def get_threat_offset_date(self, feed_type: str) -> str:
        """Return the snapshot date associated with the threat-feed offset."""
        return self.threat_feed_offset_dates.get(feed_type, "")

    def set_threat_offset(
        self,
        feed_type: str,
        offset: int,
        snapshot_date: str | None = None,
    ) -> None:
        """Set the next record offset for a threat feed day."""
        normalized_offset = max(0, int(offset))
        if normalized_offset:
            self.threat_feed_offsets[feed_type] = normalized_offset
            if snapshot_date is not None:
                self.threat_feed_offset_dates[feed_type] = snapshot_date
            else:
                self.threat_feed_offset_dates.pop(feed_type, None)
        else:
            self.threat_feed_offsets.pop(feed_type, None)
            self.threat_feed_offset_dates.pop(feed_type, None)

    def get_next_nrd_date(self, feed_type: str, default: str) -> str:
        """Return the next date to process for an NRD feed."""
        return self.nrd_dates.get(feed_type, default)

    def set_next_nrd_date(self, feed_type: str, next_date: str) -> None:
        """Set the next date for an NRD feed and clear its offset."""
        self.nrd_dates[feed_type] = next_date
        self.nrd_offsets.pop(feed_type, None)
        self.nrd_offset_dates.pop(feed_type, None)

    def get_nrd_offset(self, feed_type: str) -> int:
        """Return the record offset for the current NRD feed day."""
        return int(self.nrd_offsets.get(feed_type, 0))

    def get_nrd_offset_date(self, feed_type: str) -> str:
        """Return the snapshot date associated with the NRD offset."""
        return self.nrd_offset_dates.get(feed_type, "")

    def set_nrd_offset(
        self,
        feed_type: str,
        offset: int,
        snapshot_date: str | None = None,
    ) -> None:
        """Set the next record offset for an NRD feed day."""
        normalized_offset = max(0, int(offset))
        if normalized_offset:
            self.nrd_offsets[feed_type] = normalized_offset
            if snapshot_date is not None:
                self.nrd_offset_dates[feed_type] = snapshot_date
            else:
                self.nrd_offset_dates.pop(feed_type, None)
        else:
            self.nrd_offsets.pop(feed_type, None)
            self.nrd_offset_dates.pop(feed_type, None)
