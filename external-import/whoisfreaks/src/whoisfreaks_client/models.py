"""WhoisFreaks feed models."""

from datetime import datetime

from pydantic import BaseModel, Field


class ThreatFeedRecord(BaseModel):
    """One WhoisFreaks threat-feed CSV record."""

    domain: str = Field(min_length=1)
    threat_type: str
    confidence_score: float = Field(alias="confidence", ge=0, le=1)
    first_seen: datetime
    last_seen: datetime
    no_of_threat_matched_pivots: int = Field(
        alias="No_of_threat_matched_pivots",
        ge=0,
    )
    source_fields: dict[str, str] = Field(default_factory=dict, exclude=True)

    model_config = {"populate_by_name": True}
