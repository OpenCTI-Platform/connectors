"""Typed models for the objects in the Mirage Feed STIX bundle."""

from pydantic import AwareDatetime, BaseModel, Field


class ExternalRef(BaseModel):
    source_name: str
    external_id: str | None = None
    url: str | None = None


class MirageIndicator(BaseModel):
    id: str
    name: str
    description: str | None = None
    pattern: str
    pattern_type: str = "stix"
    indicator_types: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    confidence: int | None = Field(default=None, ge=0, le=100)
    created: AwareDatetime
    valid_from: AwareDatetime
    valid_until: AwareDatetime | None = None


class MirageAttackPattern(BaseModel):
    id: str
    name: str
    external_references: list[ExternalRef] = Field(default_factory=list)


class MirageVulnerability(BaseModel):
    id: str
    name: str
    labels: list[str] = Field(default_factory=list)


class MirageRelationship(BaseModel):
    relationship_type: str
    source_ref: str
    target_ref: str
