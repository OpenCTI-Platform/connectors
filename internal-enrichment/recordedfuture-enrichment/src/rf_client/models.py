from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RecordedFutureBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")


class CVSS2(RecordedFutureBaseModel):
    score: float | None = Field(
        description="The base CVSS score.",
        default=None,
    )
    vectorString: str | None = Field(
        description="The vector string representing the CVSS metrics.",
        default=None,
    )
    availability: str | None = Field(
        description="Impact on availability due to the vulnerability.",
        default=None,
    )
    confidentiality: str | None = Field(
        description="Impact on confidentiality due to the vulnerability.",
        default=None,
    )
    integrity: str | None = Field(
        description="Impact on integrity due to the vulnerability.",
        default=None,
    )
    accessVector: str | None = Field(
        description="The access vector of the CVSS score (e.g., Network, Adjacent)",
        default=None,
    )
    accessComplexity: str | None = Field(
        description="The complexity of the attack required to exploit the vulnerability.",
        default=None,
    )
    authentication: str | None = Field(
        description="Authentication required to exploit the vulnerability.",
        default=None,
    )
    version: str | None = Field(
        description="CVSS version used.",
        default=None,
    )
    source: str | None = Field(
        description="Source of the CVSS score (e.g., NVD, CNA, RF)",
        default=None,
    )
    lastModified: datetime | None = Field(
        description="Last modified date of the CVSS score.",
        default=None,
    )
    published: datetime | None = Field(
        description="Publish date of the CVSS score.",
        default=None,
    )


class CVSS3(RecordedFutureBaseModel):
    baseSeverity: str | None = Field(
        description="The base severity of the CVSS score.",
        default=None,
    )
    baseScore: float | None = Field(
        description="The base CVSS score.",
        default=None,
    )
    vectorString: str | None = Field(
        description="The vector string representing the CVSS metrics.",
        default=None,
    )
    attackVector: str | None = Field(
        description="The attack vector of the CVSS score (e.g., Network, Adjacent)",
        default=None,
    )
    attackComplexity: str | None = Field(
        description="The complexity of the attack required to exploit the vulnerability.",
        default=None,
    )
    attackRequirements: str | None = Field(
        description="Requirements for the attack to be successful.",
        default=None,
    )
    privilegesRequired: str | None = Field(
        description="Privileges required to exploit the vulnerability.",
        default=None,
    )
    userInteraction: str | None = Field(
        description="User interaction required to exploit the vulnerability.",
        default=None,
    )
    exploitabilityScore: float | None = Field(
        description="Score of the exploit for the vulnerability.",
        default=None,
    )
    impactScore: float | None = Field(
        description="The impact component of the CVSS score.",
        default=None,
    )
    integrityImpact: str | None = Field(
        description="Impact on integrity due to the vulnerability.",
        default=None,
    )
    confidentialityImpact: str | None = Field(
        description="Impact on confidentiality due to the vulnerability.",
        default=None,
    )
    availabilityImpact: str | None = Field(
        description="Impact on availability due to the vulnerability.",
        default=None,
    )
    scope: str | None = Field(
        description="Scope of the CVSS score (e.g., Unchanged, Changed)",
        default=None,
    )
    version: str | None = Field(
        description="CVSS version used.",
        default=None,
    )
    source: str | None = Field(
        description="Source of the CVSS score (e.g., NVD, CNA, RF)",
        default=None,
    )


class CVSS4(CVSS3):
    impactScore: float | None = Field(
        description="The impact component of the CVSS score.",
        default=None,
    )
    exploitabilityScore: float | None = Field(
        description="The exploitability component of the CVSS score.",
        default=None,
    )
    vulnerableSystemAvailability: str | None = Field(
        description="Impact on availability due to the vulnerability.",
        default=None,
    )
    subsequentSystemAvailability: str | None = Field(
        description="Impact on availability due to the vulnerability.",
        default=None,
    )
    vulnerableSystemConfidentiality: str | None = Field(
        description="Impact on confidentiality due to the vulnerability.",
        default=None,
    )
    subsequentSystemConfidentiality: str | None = Field(
        description="Impact on confidentiality due to the vulnerability.",
        default=None,
    )
    vulnerableSystemIntegrity: str | None = Field(
        description="Impact on integrity due to the vulnerability.",
        default=None,
    )
    subsequentSystemIntegrity: str | None = Field(
        description="Impact on integrity due to the vulnerability.",
        default=None,
    )


class NvdReference(RecordedFutureBaseModel):
    url: str = Field(description="Hyperlink to the NVD reference.")
    tag: str | None = Field(
        description="Resource tag for the NVD reference.",
        default=None,
    )


class AIInsights(RecordedFutureBaseModel):
    comment: str | None = Field(
        description="AI-generated summary of risk rules.",
        default=None,
    )
    text: str | None = Field(
        description="AI-generated text providing insights on the risk rules.",
        default=None,
    )
    numberOfReferences: int | None = Field(
        description="Number of references used in the AI insights.",
        default=None,
    )


class AnalystNote(RecordedFutureBaseModel):
    title: str | None = Field(
        description="Title of the analyst note.",
        default=None,
    )
    content: str | None = Field(
        description="Content of the analyst note.",
        default=None,
    )
    published: str | None = Field(
        description="Publish date of the note.",
        default=None,
    )


class Link(RecordedFutureBaseModel):
    entityType: str | None = Field(
        description="Type of the linked entity.",
        default=None,
    )
    name: str | None = Field(
        description="Name of the linked entity.",
        default=None,
    )
    riskScore: int | None = Field(
        description="Risk score of the linked entity.",
        default=None,
    )
    categories: list[str] | None = Field(
        description="Categories associated with the link.",
        default=None,
    )


class Risk(RecordedFutureBaseModel):
    score: int | None = Field(
        description="Overall risk score for the entity.",
        default=None,
    )
    criticality: int | None = Field(
        description="Severity level of the risk.",
        default=None,
    )
    criticalityLabel: str | None = Field(
        description="Label indicating the criticality of the risk.",
        default=None,
    )
    rules: int | None = Field(
        description="Number of triggered risk rules.",
        default=None,
    )
    riskString: str | None = Field(
        description="String representation of the risk score.",
        default=None,
    )
    riskSummary: str | None = Field(
        description="Summary of the risk assessment.",
        default=None,
    )
    evidenceDetails: list[dict[str, Any]] | None = Field(
        description="Evidence supporting the risk rules.",
        default=None,
    )


class VulnerabilityEnrichment(RecordedFutureBaseModel):
    # Common fields
    aiInsights: AIInsights | None = Field(
        description="AI-generated summary of risk rules.",
        default=None,
    )
    analystNotes: list[AnalystNote] | None = Field(
        description="Threat research notes for this entity.",
        default=None,
    )
    intelCard: str | None = Field(
        description="Permalink to the Intelligence Card.",
        default=None,
    )
    links: list[Link] | None = Field(
        description="High-confidence evidence-based linkages to other indicators.",
        default=None,
    )
    risk: Risk | None = Field(
        description="Risk score and evidence details.",
        default=None,
    )
    # Vulnerability-specific fields
    commonNames: list[str] | None = Field(
        description="Aliases used to refer to this vulnerability.",
        default=None,
    )
    cpe: list[str] | None = Field(
        description="CPE naming standard of affected products.",
        default=None,
    )
    cvss: CVSS2 | None = Field(
        description="CVSS v2 scores as set by NIST.",
        default=None,
    )
    cvssv3: CVSS3 | None = Field(
        description="CVSS v3 scores and associated metrics (NVD, CNA, or RFVA).",
        default=None,
    )
    cvssv4: CVSS4 | None = Field(
        description="CVSS v4 scores and associated metrics (NVD, CNA, or RFVA).",
        default=None,
    )
    lifecycleStage: str | None = Field(
        description="Lifecycle stage of the vulnerability.",
        default=None,
    )
    nvdDescription: str | None = Field(
        description="NVD description of the vulnerability.",
        default=None,
    )
    nvdReferences: list[NvdReference] | None = Field(
        description="NVD advisory references and tools.",
        default=None,
    )
