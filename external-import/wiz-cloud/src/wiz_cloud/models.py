"""Pydantic models of Wiz issuesV2 and vulnerabilityFindings payloads.

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
    """Base for every Wiz payload model."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class WizEntitySnapshot(_WizModel):
    """The cloud resource an issue was raised on."""

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
    """The detection rule that raised an issue."""

    name: str | None = None


class WizActor(_WizModel):
    """An actor behind a threat detection issue.

    Parsed and stored in the domain model, not converted to STIX yet.
    """

    id: str
    name: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    provider_unique_id: str | None = Field(default=None, alias="providerUniqueId")
    type: str | None = None


class WizThreatDetectionDetails(_WizModel):
    """Threat detection context attached to an issue."""

    actors: list[WizActor] | None = None


class WizIssue(_WizModel):
    """A Wiz issue as returned by the issuesV2 query."""

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
        """Return the headline rule name shown by the Wiz UI.

        Returns:
            The name of the first source rule that has one, or None when the
            issue carries no named rule.
        """
        for rule in self.source_rules:
            if rule.name:
                return rule.name
        return None


class WizVulnerableAsset(_WizModel):
    """The cloud resource a vulnerability finding was raised on.

    Shares its name with the issue entitySnapshot, so Systems built from
    findings resolve to the same OpenCTI entity.
    """

    id: str
    name: str
    type: str | None = None
    region: str | None = None
    provider_unique_id: str | None = Field(default=None, alias="providerUniqueId")
    cloud_provider_url: str | None = Field(default=None, alias="cloudProviderURL")
    cloud_platform: str | None = Field(default=None, alias="cloudPlatform")
    status: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class WizCvssV2(_WizModel):
    """CVSS v2 metrics of a finding. Observed entirely null in practice."""

    attack_vector: str | None = Field(default=None, alias="attackVector")
    attack_complexity: str | None = Field(default=None, alias="attackComplexity")
    confidentiality_impact: str | None = Field(
        default=None, alias="confidentialityImpact"
    )
    integrity_impact: str | None = Field(default=None, alias="integrityImpact")
    availability_impact: str | None = Field(default=None, alias="availabilityImpact")


class WizCvssV3(_WizModel):
    """CVSS v3 metrics of a finding."""

    attack_vector: str | None = Field(default=None, alias="attackVector")
    attack_complexity: str | None = Field(default=None, alias="attackComplexity")
    privileges_required: str | None = Field(default=None, alias="privilegesRequired")
    confidentiality_impact: str | None = Field(
        default=None, alias="confidentialityImpact"
    )
    integrity_impact: str | None = Field(default=None, alias="integrityImpact")
    availability_impact: str | None = Field(default=None, alias="availabilityImpact")
    exploit_code_maturity: str | None = Field(default=None, alias="exploitCodeMaturity")
    # Wiz answers a boolean where OpenCTI expects the CVSS UI string.
    user_interaction_required: bool | None = Field(
        default=None, alias="userInteractionRequired"
    )
    scope: str | None = None


class WizCvssV4(_WizModel):
    """CVSS v4 metrics of a finding. Often null."""

    attack_vector: str | None = Field(default=None, alias="attackVector")
    attack_complexity: str | None = Field(default=None, alias="attackComplexity")
    attack_requirements: str | None = Field(default=None, alias="attackRequirements")
    privileges_required: str | None = Field(default=None, alias="privilegesRequired")
    user_interaction: str | None = Field(default=None, alias="userInteraction")


class WizVulnerabilityFinding(_WizModel):
    """A finding as returned by the vulnerabilityFindings query.

    ``name`` is the CVE id and ``CVEDescription`` the CVE text, while
    ``description`` is finding-specific prose that differs per asset.
    """

    id: str
    name: str
    description: str = ""
    cve_description: str | None = Field(default=None, alias="CVEDescription")
    cvss_severity: str | None = Field(default=None, alias="CVSSSeverity")
    score: float | None = None
    severity: str | None = None
    status: str | None = None
    has_cisa_kev_exploit: bool | None = Field(default=None, alias="hasCisaKevExploit")
    portal_url: str | None = Field(default=None, alias="portalUrl")
    first_detected_at: datetime | None = Field(default=None, alias="firstDetectedAt")
    last_detected_at: datetime | None = Field(default=None, alias="lastDetectedAt")
    # Percentages in the API, converted to the 0-1 range by the converter.
    epss_percentile: float | None = Field(default=None, alias="epssPercentile")
    epss_probability: float | None = Field(default=None, alias="epssProbability")
    cvss_v2: WizCvssV2 | None = Field(default=None, alias="cvssv2")
    cvss_v3: WizCvssV3 | None = Field(default=None, alias="cvssv3")
    cvss_v4: WizCvssV4 | None = Field(default=None, alias="cvssv4")
    vulnerable_asset: WizVulnerableAsset | None = Field(
        default=None, alias="vulnerableAsset"
    )
