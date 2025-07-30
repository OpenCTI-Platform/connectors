from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class RecordedFutureBaseModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")


class CVSS2(RecordedFutureBaseModel):
    vectorString: Optional[str] = Field(
        description="The vector string representing the CVSS metrics.",
        default=None,
    )
    score: Optional[float] = Field(
        description="The base CVSS score.",
        default=None,
    )
    availability: Optional[str] = Field(
        description="Impact on availability due to the vulnerability.",
        default=None,
    )
    confidentiality: Optional[str] = Field(
        description="Impact on confidentiality due to the vulnerability.",
        default=None,
    )
    integrity: Optional[str] = Field(
        description="Impact on integrity due to the vulnerability.",
        default=None,
    )
    accessVector: Optional[str] = Field(
        description="The access vector of the CVSS score (e.g., Network, Adjacent)",
        default=None,
    )
    accessComplexity: Optional[str] = Field(
        description="The complexity of the attack required to exploit the vulnerability.",
        default=None,
    )
    authentication: Optional[str] = Field(
        description="Authentication required to exploit the vulnerability.",
        default=None,
    )
    version: Optional[str] = Field(
        description="CVSS version used.",
        default=None,
    )
    source: Optional[str] = Field(
        description="Source of the CVSS score (e.g., NVD, CNA, RF)",
        default=None,
    )
    lastModified: Optional[datetime] = Field(
        description="Last modified date of the CVSS score.",
        default=None,
    )
    published: Optional[datetime] = Field(
        description="Publish date of the CVSS score.",
        default=None,
    )


class CVSS3(RecordedFutureBaseModel):
    vectorString: Optional[str] = Field(
        description="The vector string representing the CVSS metrics.",
        default=None,
    )
    baseScore: Optional[float] = Field(
        description="The base CVSS score.",
        default=None,
    )
    baseSeverity: Optional[str] = Field(
        description="The base severity of the CVSS score.",
        default=None,
    )
    attackVector: Optional[str] = Field(
        description="The attack vector of the CVSS score (e.g., Network, Adjacent)",
        default=None,
    )
    attackComplexity: Optional[str] = Field(
        description="The complexity of the attack required to exploit the vulnerability.",
        default=None,
    )
    attackRequirements: Optional[str] = Field(
        description="Requirements for the attack to be successful.",
        default=None,
    )
    privilegesRequired: Optional[str] = Field(
        description="Privileges required to exploit the vulnerability.",
        default=None,
    )
    userInteraction: Optional[str] = Field(
        description="User interaction required to exploit the vulnerability.",
        default=None,
    )
    exploitabilityScore: Optional[float] = Field(
        description="Score of the exploit for the vulnerability.",
        default=None,
    )
    impactScore: Optional[float] = Field(
        description="The impact component of the CVSS score.",
        default=None,
    )
    integrityImpact: Optional[str] = Field(
        description="Impact on integrity due to the vulnerability.",
        default=None,
    )
    confidentialityImpact: Optional[str] = Field(
        description="Impact on confidentiality due to the vulnerability.",
        default=None,
    )
    availabilityImpact: Optional[str] = Field(
        description="Impact on availability due to the vulnerability.",
        default=None,
    )
    scope: Optional[str] = Field(
        description="Scope of the CVSS score (e.g., Unchanged, Changed)",
        default=None,
    )
    version: Optional[str] = Field(
        description="CVSS version used.",
        default=None,
    )
    source: Optional[str] = Field(
        description="Source of the CVSS score (e.g., NVD, CNA, RF)",
        default=None,
    )


class CVSS4(BaseModel):
    vectorString: Optional[str] = Field(
        description="The vector string representing the CVSS metrics.",
        default=None,
    )
    baseScore: Optional[float] = Field(
        description="The base CVSS score.",
        default=None,
    )
    baseSeverity: Optional[str] = Field(
        description="The base severity of the CVSS score.",
        default=None,
    )
    attackVector: Optional[str] = Field(
        description="The attack vector of the CVSS score (e.g., Network, Adjacent)",
        default=None,
    )
    attackComplexity: Optional[str] = Field(
        description="The complexity of the attack required to exploit the vulnerability.",
        default=None,
    )
    attackRequirements: Optional[str] = Field(
        description="Requirements for the attack to be successful.",
        default=None,
    )
    privilegesRequired: Optional[str] = Field(
        description="Privileges required to exploit the vulnerability.",
        default=None,
    )
    userInteraction: Optional[str] = Field(
        description="User interaction required to exploit the vulnerability.",
        default=None,
    )
    vulnerableSystemAvailability: Optional[str] = Field(
        description="Impact on availability due to the vulnerability.",
        default=None,
    )
    subsequentSystemAvailability: Optional[str] = Field(
        description="Impact on availability due to the vulnerability.",
        default=None,
    )
    vulnerableSystemConfidentiality: Optional[str] = Field(
        description="Impact on confidentiality due to the vulnerability.",
        default=None,
    )
    subsequentSystemConfidentiality: Optional[str] = Field(
        description="Impact on confidentiality due to the vulnerability.",
        default=None,
    )
    vulnerableSystemIntegrity: Optional[str] = Field(
        description="Impact on integrity due to the vulnerability.",
        default=None,
    )
    subsequentSystemIntegrity: Optional[str] = Field(
        description="Impact on integrity due to the vulnerability.",
        default=None,
    )
    version: Optional[str] = Field(
        description="CVSS version used.",
        default=None,
    )
    source: Optional[str] = Field(
        description="Source of the CVSS score (e.g., NVD, CNA, RF)",
        default=None,
    )


class NvdReference(RecordedFutureBaseModel):
    url: str = Field(
        description="Hyperlink to the NVD reference.",
    )
    tags: Optional[list[str]] = Field(
        description="Resource tags for the NVD reference.",
        default=[],
    )


class AIInsights(RecordedFutureBaseModel):
    comment: Optional[str] = Field(
        description="AI-generated summary of risk rules.",
        default=None,
    )
    text: Optional[str] = Field(
        description="AI-generated text providing insights on the risk rules.",
        default=None,
    )
    numberOfReferences: Optional[int] = Field(
        description="Number of references used in the AI insights.",
        default=None,
    )


class AnalystNoteAttributeNoteEntity(RecordedFutureBaseModel):
    id: Optional[str] = Field(
        description="",
        default=None,
    )
    name: Optional[str] = Field(
        description="",
        default=None,
    )
    type: Optional[str] = Field(
        description="",
        default=None,
    )
    description: Optional[str] = Field(
        description="",
        default=None,
    )


class AnalystNoteAttributeContextEntity(RecordedFutureBaseModel):
    id: Optional[str] = Field(
        description="",
        default=None,
    )
    name: Optional[str] = Field(
        description="",
        default=None,
    )
    type: Optional[str] = Field(
        description="",
        default=None,
    )


class AnalystNoteAttribute(RecordedFutureBaseModel):
    published: Optional[datetime] = Field(
        description="",
        default=None,
    )
    title: Optional[str] = Field(
        description="",
        default=None,
    )
    text: Optional[str] = Field(
        description="",
        default=None,
    )
    attachment: Optional[str] = Field(
        description="",
        default=None,
    )
    topic: dict = Field(
        description="",
        default=None,
    )
    note_entities: Optional[list[AnalystNoteAttributeNoteEntity]] = Field(
        description="",
        default=None,
    )
    context_entities: Optional[list[AnalystNoteAttributeContextEntity]] = Field(
        description="",
        default=None,
    )


class AnalystNoteSource(RecordedFutureBaseModel):
    id: Optional[str] = Field(
        description="",
        default=None,
    )
    name: Optional[str] = Field(
        description="",
        default=None,
    )
    type: Optional[str] = Field(
        description="",
        default=None,
    )


class AnalystNote(RecordedFutureBaseModel):
    attributes: Optional[AnalystNoteAttribute] = Field(
        description="",
        default=None,
    )
    source: Optional[AnalystNoteSource] = Field(
        description="",
        default=None,
    )


class Link(RecordedFutureBaseModel):
    count: Optional[int] = Field(
        description="Count of the link.",
        default=None,
    )
    type: Optional[str] = Field(
        description="Type of the link.",
        default=None,
    )


class Links(RecordedFutureBaseModel):
    hits: Optional[list] = Field(
        description="",
        default=None,
    )
    counts: Optional[list] = Field(
        description="",
        default=None,
    )
    method_aggregates: Optional[list[Link]] = Field(
        description="",
        default=None,
    )


class Risk(RecordedFutureBaseModel):
    score: Optional[int] = Field(
        description="Overall risk score for the entity.",
        default=None,
    )
    criticality: Optional[int] = Field(
        description="Severity level of the risk.",
        default=None,
    )
    criticalityLabel: Optional[str] = Field(
        description="Label indicating the criticality of the risk.",
        default=None,
    )
    rules: Optional[int] = Field(
        description="Number of triggered risk rules.",
        default=None,
    )
    riskString: Optional[str] = Field(
        description="String representation of the risk score.",
        default=None,
    )
    riskSummary: Optional[str] = Field(
        description="Summary of the risk assessment.",
        default=None,
    )
    evidenceDetails: Optional[list[dict[str, Any]]] = Field(
        description="Evidence supporting the risk rules.",
        default=None,
    )


class VulnerabilityEnrichment(RecordedFutureBaseModel):
    # Common fields
    intelCard: str = Field(
        description="Permalink to the Intelligence Card.",
    )
    links: Links = Field(
        description="High-confidence evidence-based linkages to other indicators.",
    )
    aiInsights: Optional[AIInsights] = Field(
        description="AI-generated summary of risk rules.",
        default=None,
    )
    analystNotes: Optional[list[AnalystNote]] = Field(
        description="Threat research notes for this entity.",
        default=None,
    )
    risk: Optional[Risk] = Field(
        description="Risk score and evidence details.",
        default=None,
    )
    # Vulnerability-specific fields
    commonNames: list[str] = Field(
        description="Aliases used to refer to this vulnerability.",
    )
    cvss: CVSS2 = Field(
        description="CVSS v2 scores as set by NIST.",
    )
    cvssv3: CVSS3 = Field(
        description="CVSS v3 scores and associated metrics (NVD, CNA, or RFVA).",
    )
    cvssv4: CVSS4 = Field(
        description="CVSS v4 scores and associated metrics (NVD, CNA, or RFVA).",
    )
    lifecycleStage: str = Field(
        description="Lifecycle stage of the vulnerability.",
    )
    cpe: list[str] = Field(
        description="CPE naming standard of affected products.",
    )
    nvdDescription: str = Field(
        description="NVD description of the vulnerability.",
    )
    nvdReferences: list[NvdReference] = Field(
        description="NVD advisory references and tools.",
    )
