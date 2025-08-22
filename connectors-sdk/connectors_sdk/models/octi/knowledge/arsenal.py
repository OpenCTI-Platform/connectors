"""Offer arsenal OpenCTI entities."""

from typing import Optional

from connectors_sdk.models.octi._common import MODEL_REGISTRY, BaseIdentifiedEntity
from connectors_sdk.models.octi.enums import CvssSeverity
from pycti import Vulnerability as PyctiVulnerability
from pydantic import Field
from stix2.v21 import Vulnerability as Stix2Vulnerability


@MODEL_REGISTRY.register
class Vulnerability(BaseIdentifiedEntity):
    """Represents a vulnerability entity."""

    name: str = Field(
        description="Name of the vulnerability.",
        min_length=1,
    )
    description: Optional[str] = Field(
        description="Description of the vulnerability.",
        default=None,
    )
    labels: Optional[list[str]] = Field(
        description="Labels of the vulnerability.",
        default=None,
    )
    aliases: Optional[list[str]] = Field(
        description="Vulnerability aliases",
        default=None,
    )
    score: Optional[int] = Field(
        description="Score of the vulnerability.",
        default=None,
        ge=0,
        le=100,
    )
    epss_score: Optional[float] = Field(
        description="EPSS score.",
        default=None,
        ge=0,
        le=1,
    )
    epss_percentile: Optional[float] = Field(
        description="EPSS percentile.",
        default=None,
        ge=0,
        le=1,
    )
    is_cisa_kev: Optional[bool] = Field(
        description="Whether vulnerability is a CISA Known Exploited Vulnerability.",
        default=None,
    )
    cvss_v2_vector_string: Optional[str] = Field(
        description="CVSS v2 vector string.",
        default=None,
    )
    cvss_v2_base_score: Optional[float] = Field(
        description="Reflects the severity score of a vulnerability according to its intrinsic characteristics.",
        default=None,
    )
    cvss_v2_access_vector: Optional[str] = Field(
        description="Reflects how the vulnerability is exploited. Abbreviation: AV",
        default=None,
    )
    cvss_v2_access_complexity: Optional[str] = Field(
        description="Measures the complexity of the attack required to exploit the vulnerability "
        "once an attacker has gained access to the target system. Abbreviation: AC",
        default=None,
    )
    cvss_v2_authentication: Optional[str] = Field(
        description="Measures the number of times an attacker must authenticate "
        "to a target in order to exploit a vulnerability. Abbreviation: Au",
        default=None,
    )
    cvss_v2_confidentiality_impact: Optional[str] = Field(
        description="Measures the impact on confidentiality of a successfully exploited vulnerability. Abbreviation: C",
        default=None,
    )
    cvss_v2_integrity_impact: Optional[str] = Field(
        description="Measures the impact to integrity of a successfully exploited vulnerability. Abbreviation: I",
        default=None,
    )
    cvss_v2_availability_impact: Optional[str] = Field(
        description="Measures the impact to availability of a successfully exploited vulnerability. Abbreviation: A",
        default=None,
    )
    cvss_v2_exploitability: Optional[str] = Field(
        description="Measures the current state of exploit techniques or code availability. Abbreviation: E",
        default=None,
    )
    cvss_v3_vector_string: Optional[str] = Field(
        description="CVSS v3 vector string.",
        default=None,
    )
    cvss_v3_base_score: Optional[float] = Field(
        description="Reflects the severity score of a vulnerability according to its intrinsic characteristics.",
        default=None,
    )
    cvss_v3_base_severity: Optional[CvssSeverity] = Field(
        description="Reflects the severity level of a vulnerability according to its intrinsic characteristics.",
        default=None,
    )
    cvss_v3_attack_vector: Optional[str] = Field(
        description="Reflects the context by which vulnerability exploitation is possible. Abbreviation: AV",
        default=None,
    )
    cvss_v3_attack_complexity: Optional[str] = Field(
        description="Describes the conditions beyond the attacker's control that must "
        "exist in order to exploit the vulnerability. Abbreviation: AC",
        default=None,
    )
    cvss_v3_privileges_required: Optional[str] = Field(
        description="Describes the level of privileges an attacker must possess before "
        "successfully exploiting the vulnerability. Abbreviation: PR",
        default=None,
    )
    cvss_v3_user_interaction: Optional[str] = Field(
        description="Captures the requirement for a user, other than the attacker, "
        "to participate in the successful compromise of the vulnerable component. Abbreviation: UI",
        default=None,
    )
    cvss_v3_integrity_impact: Optional[str] = Field(
        description="Measures the impact to integrity of a successfully exploited vulnerability. Abbreviation: I",
        default=None,
    )
    cvss_v3_availability_impact: Optional[str] = Field(
        description="Measures the impact to the availability of the impacted component "
        "resulting from a successfully exploited vulnerability. Abbreviation: A",
        default=None,
    )
    cvss_v3_confidentiality_impact: Optional[str] = Field(
        description="Measures the impact to the confidentiality of the information "
        "resources managed by a software component due to a successfully exploited vulnerability. Abbreviation: C",
        default=None,
    )
    cvss_v3_scope: Optional[str] = Field(
        description="The ability for a vulnerability in one software component "
        "to impact resources beyond its means, or privileges. Abbreviation: S",
        default=None,
    )
    cvss_v3_exploit_code_maturity: Optional[str] = Field(
        description="Measures the likelihood of the vulnerability being attacked, and is typically "
        "based on the current state of exploit techniques, exploit code availability, or active, 'in-the-wild' exploitation. Abbreviation: E",
        default=None,
    )
    cvss_v4_vector_string: Optional[str] = Field(
        description="CVSS v4 vector string.",
        default=None,
    )
    cvss_v4_base_score: Optional[float] = Field(
        description="Reflects the severity score of a vulnerability according to its intrinsic characteristics.",
        default=None,
    )
    cvss_v4_base_severity: Optional[CvssSeverity] = Field(
        description="Reflects the severity level of a vulnerability according to its intrinsic characteristics.",
        default=None,
    )
    cvss_v4_attack_vector: Optional[str] = Field(
        description="Reflects the context by which vulnerability exploitation is possible. Abbreviation: AV",
        default=None,
    )
    cvss_v4_attack_complexity: Optional[str] = Field(
        description="Captures measurable actions that must be taken by the attacker to actively evade or circumvent "
        "existing built-in security-enhancing conditions in order to obtain a working exploit. Abbreviation: AC",
        default=None,
    )
    cvss_v4_attack_requirements: Optional[str] = Field(
        description="Captures the prerequisite deployment and execution conditions or variables "
        "of the vulnerable system that enable the attack. Abbreviation: AT",
        default=None,
    )
    cvss_v4_privileges_required: Optional[str] = Field(
        description="Describes the level of privileges an attacker must possess prior to "
        "successfully exploiting the vulnerability. Abbreviation: PR",
        default=None,
    )
    cvss_v4_user_interaction: Optional[str] = Field(
        description="Captures the requirement for a human user, other than the attacker, to participate "
        "in the successful compromise of the vulnerable system. Abbreviation: UI",
        default=None,
    )
    cvss_v4_vs_confidentiality_impact: Optional[str] = Field(
        description="Measures the impact to the confidentiality of the information managed by "
        "the system due to a successfully exploited vulnerability. Abbreviation: VC",
        default=None,
    )
    cvss_v4_ss_confidentiality_impact: Optional[str] = Field(
        description="Measures the impact to the confidentiality of the information managed by "
        "the system due to a successfully exploited vulnerability. Abbreviation: SC",
        default=None,
    )
    cvss_v4_vs_integrity_impact: Optional[str] = Field(
        description="Measures the impact to integrity of a successfully exploited vulnerability. Abbreviation: VI",
        default=None,
    )
    cvss_v4_ss_integrity_impact: Optional[str] = Field(
        description="Measures the impact to integrity of a successfully exploited vulnerability. Abbreviation: SI",
        default=None,
    )
    cvss_v4_vs_availability_impact: Optional[str] = Field(
        description="Measures the impact to the availability of the impacted system resulting "
        "from a successfully exploited vulnerability. Abbreviation: VA",
        default=None,
    )
    cvss_v4_ss_availability_impact: Optional[str] = Field(
        description="Measures the impact to the availability of the impacted system resulting "
        "from a successfully exploited vulnerability. Abbreviation: SA",
        default=None,
    )
    cvss_v4_exploit_maturity: Optional[str] = Field(
        description="Measures the likelihood of the vulnerability being attacked, and is based on the current state of "
        "exploit techniques, exploit code availability, or active, “in-the-wild” exploitation. Abbreviation: E",
        default=None,
    )

    def to_stix2_object(self) -> Stix2Vulnerability:
        """Make Vulnerability STIX2.1 object."""
        return Stix2Vulnerability(
            id=PyctiVulnerability.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            labels=self.labels,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            created_by_ref=self.author.id if self.author else None,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            x_opencti_aliases=self.aliases,
            x_opencti_score=self.score,
            x_opencti_epss_score=self.epss_score,
            x_opencti_epss_percentile=self.epss_percentile,
            x_opencti_cisa_kev=self.is_cisa_kev,
            # Cvss v3 (default on OpenCTI)
            x_opencti_cvss_vector_string=self.cvss_v3_vector_string,
            x_opencti_cvss_base_score=self.cvss_v3_base_score,
            x_opencti_cvss_base_severity=self.cvss_v3_base_severity,
            x_opencti_cvss_attack_vector=self.cvss_v3_attack_vector,
            x_opencti_cvss_attack_complexity=self.cvss_v3_attack_complexity,
            x_opencti_cvss_privileges_required=self.cvss_v3_privileges_required,
            x_opencti_cvss_user_interaction=self.cvss_v3_user_interaction,
            x_opencti_cvss_integrity_impact=self.cvss_v3_integrity_impact,
            x_opencti_cvss_availability_impact=self.cvss_v3_availability_impact,
            x_opencti_cvss_confidentiality_impact=self.cvss_v3_confidentiality_impact,
            x_opencti_cvss_scope=self.cvss_v3_scope,
            x_opencti_cvss_exploit_code_maturity=self.cvss_v3_exploit_code_maturity,
            # CVSS v2
            x_opencti_cvss_v2_vector_string=self.cvss_v2_vector_string,
            x_opencti_cvss_v2_access_vector=self.cvss_v2_access_vector,
            x_opencti_cvss_v2_access_complexity=self.cvss_v2_access_complexity,
            x_opencti_cvss_v2_authentication=self.cvss_v2_authentication,
            x_opencti_cvss_v2_confidentiality_impact=self.cvss_v2_confidentiality_impact,
            x_opencti_cvss_v2_integrity_impact=self.cvss_v2_integrity_impact,
            x_opencti_cvss_v2_availability_impact=self.cvss_v2_availability_impact,
            x_opencti_cvss_v2_exploitability=self.cvss_v2_exploitability,
            # CVSS v4
            x_opencti_cvss_v4_vector_string=self.cvss_v4_vector_string,
            x_opencti_cvss_v4_base_score=self.cvss_v4_base_score,
            x_opencti_cvss_v4_base_severity=self.cvss_v4_base_severity,
            x_opencti_cvss_v4_attack_vector=self.cvss_v4_attack_vector,
            x_opencti_cvss_v4_attack_complexity=self.cvss_v4_attack_complexity,
            x_opencti_cvss_v4_attack_requirements=self.cvss_v4_attack_requirements,
            x_opencti_cvss_v4_privileges_required=self.cvss_v4_privileges_required,
            x_opencti_cvss_v4_user_interaction=self.cvss_v4_user_interaction,
            x_opencti_cvss_v4_confidentiality_impact_v=self.cvss_v4_vs_confidentiality_impact,
            x_opencti_cvss_v4_confidentiality_impact_s=self.cvss_v4_ss_confidentiality_impact,
            x_opencti_cvss_v4_integrity_impact_v=self.cvss_v4_vs_integrity_impact,
            x_opencti_cvss_v4_integrity_impact_s=self.cvss_v4_ss_integrity_impact,
            x_opencti_cvss_v4_availability_impact_v=self.cvss_v4_vs_availability_impact,
            x_opencti_cvss_v4_availability_impact_s=self.cvss_v4_ss_availability_impact,
            x_opencti_cvss_v4_exploit_maturity=self.cvss_v4_exploit_maturity,
        )


# See https://docs.pydantic.dev/latest/errors/usage_errors/#class-not-fully-defined (consulted on 2025-06-10)
MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    import doctest

    doctest.testmod()
