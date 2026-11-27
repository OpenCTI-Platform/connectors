"""STIX locations and sectors paired with how GTI associated them with an entity.

Dates become the relationship start and stop times, confidence and note its description.
"""

from datetime import datetime

from pydantic import BaseModel
from stix2.v21 import Identity, Location  # type: ignore


class LocationWithTiming(BaseModel):
    """Container for a STIX Location object with timing metadata."""

    model_config = {"arbitrary_types_allowed": True}

    location: Location
    confidence: str | None = None  # GTI confidence, e.g. "confirmed"
    note: str | None = None  # GTI description of the association
    source: str | None = None  # GTI information supplier
    subject: str | None = (
        None  # Detail the note is about, e.g. the industry of a sector
    )
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    is_targeted: bool = False
    is_source: bool = False


class IdentityWithTiming(BaseModel):
    """Container for a STIX Identity object with timing metadata."""

    model_config = {"arbitrary_types_allowed": True}

    identity: Identity
    confidence: str | None = None  # GTI confidence, e.g. "confirmed"
    note: str | None = None  # GTI description of the association
    source: str | None = None  # GTI information supplier
    subject: str | None = (
        None  # Detail the note is about, e.g. the industry of a sector
    )
    first_seen: datetime | None = None
    last_seen: datetime | None = None
