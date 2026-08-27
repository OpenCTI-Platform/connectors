"""Pydantic models of Wiz issuesV2 payloads.

Shapes validated against a captured tenant payload (2026-08-24), which
established:
- description can be an empty string (three of 25 sampled nodes)
- threatDetectionDetails can be present with actors: null
- entitySnapshot fields region / providerId / cloudProviderURL are often
  empty strings rather than null
- tags can be {} and keys can contain slashes ("Wiz/wz")
- the same entitySnapshot recurs across issues (converter must dedup)
- sourceRules answers a plain { name } selection, no inline fragments needed

extra="allow" keeps the connector alive across Wiz schema additions; the
converter only reads declared fields.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class _WizModel(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class WizEntitySnapshot(_WizModel):
    id: str
    name: str
    type: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    cloud_platform: str | None = Field(default=None, alias="cloudPlatform")
    cloud_provider_url: str | None = Field(default=None, alias="cloudProviderURL")
    provider_id: str | None = Field(default=None, alias="providerId")
    region: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class WizSourceRule(_WizModel):
    name: str | None = None


class WizActor(_WizModel):
    """Parsed and stored in the domain model, not converted to STIX yet."""

    id: str
    name: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    provider_unique_id: str | None = Field(default=None, alias="providerUniqueId")
    type: str | None = None


class WizThreatDetectionDetails(_WizModel):
    actors: list[WizActor] | None = None


class WizIssue(_WizModel):
    id: str
    type: str
    severity: str
    status: str
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime | None = Field(default=None, alias="updatedAt")
    first_event_at: datetime | None = Field(default=None, alias="firstEventAt")
    last_event_at: datetime | None = Field(default=None, alias="lastEventAt")
    description: str = ""
    open_reason: str | None = Field(default=None, alias="openReason")
    url: str | None = None
    entity_snapshot: WizEntitySnapshot | None = Field(
        default=None, alias="entitySnapshot"
    )
    source_rules: list[WizSourceRule] = Field(default_factory=list, alias="sourceRules")
    threat_detection_details: WizThreatDetectionDetails | None = Field(
        default=None, alias="threatDetectionDetails"
    )

    @property
    def rule_name(self) -> str | None:
        for rule in self.source_rules:
            if rule.name:
                return rule.name
        return None
