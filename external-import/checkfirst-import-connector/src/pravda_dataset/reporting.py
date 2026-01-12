from __future__ import annotations

"""Run reporting utilities.

The connector records lightweight metrics (counts and error/skip reasons) to
help with troubleshooting and operational visibility.
"""

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SkipReason(str, Enum):
    """Categorized reasons for skipping data or recording errors."""

    FILE_TOO_LARGE = "file_too_large"
    FILE_READ_ERROR = "file_read_error"
    HEADER_INVALID = "header_invalid"

    ROW_TOO_LARGE = "row_too_large"
    ROW_MISSING_REQUIRED_FIELDS = "row_missing_required_fields"
    ROW_INVALID_PUBLICATION_DATE = "row_invalid_publication_date"
    ROW_MAPPING_ERROR = "row_mapping_error"

    BUNDLE_SEND_ERROR = "bundle_send_error"


@dataclass
class RunReport:
    """Accumulates basic counters for a connector run."""

    files_seen: int = 0
    files_processed: int = 0
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

    def to_summary(self) -> dict[str, Any]:
        """Convert the report to a JSON-serializable summary."""
        return {
            "files_seen": self.files_seen,
            "files_processed": self.files_processed,
            "rows_seen": self.rows_seen,
            "rows_mapped": self.rows_mapped,
            "bundles_sent": self.bundles_sent,
            "skipped": dict(self.skipped),
            "errors": dict(self.errors),
        }
