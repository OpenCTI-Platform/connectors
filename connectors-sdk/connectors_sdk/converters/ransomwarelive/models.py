"""Ransomware.live input models.

They describe a victim publication from the ``/recentvictims`` API and the
matching group entry from ``/groups``, limited to the fields the converter
reads. Resolving the group entry for a victim is the caller's job.
"""

from datetime import datetime, timezone
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field


def _assume_utc(value: datetime) -> datetime:
    """Read a datetime without timezone as UTC, as the ``stix2`` library does."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


UtcDatetime = Annotated[datetime, AfterValidator(_assume_utc)]


class RansomwareLiveGroupLocation(BaseModel):
    """One leak site of a group."""

    fqdn: str | None = None
    slug: str | None = None
    title: str | None = None


class RansomwareLiveGroup(BaseModel):
    """One group entry from the ``/groups`` API."""

    name: str
    altname: str | None = None
    description: str | None = None
    url: str | None = None
    locations: list[RansomwareLiveGroupLocation] = Field(default_factory=list)


class RansomwareLiveVictim(BaseModel):
    """One victim publication from the ``/recentvictims`` API."""

    victim: str
    group: str
    attackdate: UtcDatetime
    discovered: UtcDatetime | None = None
    activity: str | None = None
    country: str | None = None
    domain: str | None = None
    description: str | None = None
    screenshot: str | None = None
    website: str | None = None
    post_url: str | None = None


class RansomwareLiveVictimInput(BaseModel):
    """A victim publication with the entry of its group, when known."""

    victim: RansomwareLiveVictim
    group: RansomwareLiveGroup | None = None
