"""Value objects returned by the AbuseIPDB TAXII client."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TaxiiPage:
    """One validated page of a TAXII ``objects`` response."""

    objects: list[dict[str, Any]]
    more: bool
    next_cursor: str | None
    added_last: str | None
