"""Run reporting utilities.

The connector records lightweight metrics (counts and error/skip reasons) to
help with troubleshooting and operational visibility.

"""

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum


class SkipReason(str, Enum):
    """Categorized reasons for skipping data or recording errors."""

    ROW_TOO_LARGE = "row_too_large"
    ROW_MISSING_REQUIRED_FIELDS = "row_missing_required_fields"
    ROW_INVALID_PUBLICATION_DATE = "row_invalid_publication_date"
    ROW_MAPPING_ERROR = "row_mapping_error"

    API_ERROR = "api_error"
    BUNDLE_SEND_ERROR = "bundle_send_error"


@dataclass
class RunReport:
    """Accumulates basic counters for a connector run."""

    pages_fetched: int = 0
    rows_seen: int = 0
    rows_mapped: int = 0
    bundles_sent: int = 0

    skipped: Counter[str] = field(default_factory=Counter)
    errors: Counter[str] = field(default_factory=Counter)

    def skip(self, reason: SkipReason, *, count: int = 1) -> None:
        """Record that we skipped processing for a known reason."""
        self.skipped[reason.value] += count

    def error(self, reason: SkipReason, *, count: int = 1) -> None:
        """Record that we encountered an error for a known reason."""
        self.errors[reason.value] += count

    def to_summary(self) -> str:
        """Return a human-readable summary string for ``to_processed()``."""
        parts = [
            f"pages={self.pages_fetched}",
            f"rows_seen={self.rows_seen}",
            f"mapped={self.rows_mapped}",
            f"bundles={self.bundles_sent}",
        ]
        if self.skipped:
            parts.append(f"skipped={dict(self.skipped)}")
        if self.errors:
            parts.append(f"errors={dict(self.errors)}")
        return f"Checkfirst run: {', '.join(parts)}"
