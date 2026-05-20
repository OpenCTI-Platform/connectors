"""Pydantic models for GTI IOC delta NDJSON format."""

from pydantic import BaseModel, Field


class IOCDeltaVerdict(BaseModel):
    value: str | None = Field(None)


class IOCDeltaSeverity(BaseModel):
    value: str | None = Field(None)


class IOCDeltaThreatScore(BaseModel):
    value: int | None = Field(None)


class IOCDeltaGTIAssessment(BaseModel):
    verdict: IOCDeltaVerdict | None = Field(None)
    severity: IOCDeltaSeverity | None = Field(None)
    threat_score: IOCDeltaThreatScore | None = Field(None)


class IOCDeltaRelationshipItemAttributes(BaseModel):
    collection_type: str | None = Field(None)
    name: str | None = Field(None)


class IOCDeltaRelationshipItem(BaseModel):
    type: str | None = Field(None)
    id: str | None = Field(None)
    attributes: IOCDeltaRelationshipItemAttributes | None = Field(None)


class IOCDeltaRelationshipAttackTechniqueItem(BaseModel):
    type: str | None = Field(None)
    id: str | None = Field(None)


class IOCDeltaRelationshipData(BaseModel):
    data: list[IOCDeltaRelationshipItem] = Field(default_factory=list)


class IOCDeltaRelationships(BaseModel):
    malware_families: IOCDeltaRelationshipData | None = Field(None)
    campaigns: IOCDeltaRelationshipData | None = Field(None)
    threat_actors: IOCDeltaRelationshipData | None = Field(None)
    reports: IOCDeltaRelationshipData | None = Field(None)
    software_toolkits: IOCDeltaRelationshipData | None = Field(None)
    vulnerabilities: IOCDeltaRelationshipData | None = Field(None)
    attack_techniques: IOCDeltaRelationshipAttackTechniqueItem | None = Field(None)


class IOCDeltaAttributes(BaseModel):
    # File fields
    sha256: str | None = Field(None)
    md5: str | None = Field(None)
    sha1: str | None = Field(None)
    meaningful_name: str | None = Field(None)
    names: list[str] | None = Field(None)
    size: int | None = Field(None)
    # URL fields
    url: str | None = Field(None)
    # Common fields
    gti_assessment: IOCDeltaGTIAssessment | None = Field(None)
    creation_date: int | None = Field(None)
    last_modification_date: int | None = Field(None)


class IOCDeltaEntry(BaseModel):
    """A single IOC entry from the delta NDJSON stream."""

    id: str = Field(...)
    type: str = Field(...)  # "file", "ip_address", "domain", "url"
    attributes: IOCDeltaAttributes | None = Field(None)
    relationships: IOCDeltaRelationships | None = Field(None)
