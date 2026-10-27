"""WhoisFreaks input models.

Copied from ``external-import/whoisfreaks/src/whoisfreaks_client/models.py``.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class WhoisFreaksThreatFeedRecord(BaseModel):
    """One WhoisFreaks threat-feed CSV record."""

    model_config = ConfigDict(populate_by_name=True)

    domain: str = Field(min_length=1)
    threat_type: str
    confidence_score: float = Field(alias="confidence", ge=0, le=1)
    first_seen: datetime
    last_seen: datetime
    no_of_threat_matched_pivots: int = Field(
        alias="No_of_threat_matched_pivots",
        ge=0,
    )
    # All CSV columns in source order, when the client kept them.
    source_fields: dict[str, str] = Field(default_factory=dict, exclude=True)
