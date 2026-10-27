"""CrowdStrike input models.

They describe the CrowdStrike Intel API actor entity, limited to the fields
the converters read.
"""

from pydantic import BaseModel, Field


class CrowdStrikeEntity(BaseModel):
    """A CrowdStrike reference entity (country, region, industry, motivation)."""

    id: int | None = None
    slug: str | None = None
    value: str | None = None


class CrowdStrikeThreat(BaseModel):
    """A malware family used or developed by an actor."""

    family_name: str | None = None


class CrowdStrikeActor(BaseModel):
    """One actor from the CrowdStrike Intel ``/intel/entities/actors`` API."""

    id: int
    name: str
    url: str | None = None
    description: str | None = None
    rich_text_description: str | None = None
    short_description: str | None = None
    known_as: str | None = None
    actor_type: str | None = None
    # Unix timestamps; 0 or negative means unknown.
    first_activity_date: int | None = None
    last_activity_date: int | None = None
    motivations: list[CrowdStrikeEntity] | None = None
    origins: list[CrowdStrikeEntity] | None = None
    # Target countries may also contain regions (slug longer than 2 characters).
    target_countries: list[CrowdStrikeEntity] | None = None
    target_industries: list[CrowdStrikeEntity] | None = None
    uses_threats: list[CrowdStrikeThreat] | None = None
    develops_threats: list[CrowdStrikeThreat] | None = None


class CrowdStrikeActorInput(BaseModel):
    """An actor with its MITRE ATT&CK identifiers.

    ``mitre_attack_ids`` are the raw identifiers returned by the
    ``/intel/queries/mitre/v1`` API, e.g. ``scion-spider_TA0002_T1059.001``.
    """

    actor: CrowdStrikeActor
    mitre_attack_ids: list[str] = Field(default_factory=list)


class CrowdStrikeReportPdf(BaseModel):
    """The PDF attachment of a CrowdStrike Intel report."""

    report_id: int
    file_name: str
    content: bytes
