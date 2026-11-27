"""GTI assessment models shared by the domain, file, IP address and URL IOCs."""

from pydantic import BaseModel, Field


class Verdict(BaseModel):
    """Model representing a GTI assessment verdict."""

    value: str | None = Field(
        None, description="Verdict value (e.g., 'VERDICT_BENIGN', 'VERDICT_MALICIOUS')."
    )


class Severity(BaseModel):
    """Model representing a GTI assessment severity."""

    value: str | None = Field(
        None, description="Severity value (e.g., 'SEVERITY_LOW', 'SEVERITY_HIGH')."
    )


class ThreatScore(BaseModel):
    """Model representing the GTI threat score."""

    value: int | None = Field(
        None, description="Threat score, integer between 0 and 100."
    )


class ContributingFactors(BaseModel):
    """Signals contributing to the GTI verdict and severity of an IOC."""

    mandiant_analyst_benign: bool | None = Field(
        None, description="Indicator if an analyst marked benign."
    )
    mandiant_analyst_malicious: bool | None = Field(
        None, description="Indicator if an analyst marked malicious."
    )
    google_malware_analysis: bool | None = Field(
        None, description="Detected by Google malware analysis."
    )
    google_botnet_emulation: bool | None = Field(
        None, description="Detected by Google botnet analysis."
    )
    google_mobile_malware_analysis: bool | None = Field(
        None, description="Detected by Google mobile malware analysis."
    )
    google_malware_similarity: bool | None = Field(
        None, description="Detected by Google malware similarity."
    )
    google_malware_analysis_auto: bool | None = Field(
        None, description="Detected by Google automated malware analysis."
    )
    mandiant_association_report: bool | None = Field(
        None, description="Associated with an intelligence report."
    )
    mandiant_association_actor: bool | None = Field(
        None, description="Associated with a threat actor."
    )
    mandiant_association_malware: bool | None = Field(
        None, description="Associated with a malware family."
    )
    gti_confidence_score: int | None = Field(
        None,
        description="GTI machine learning confidence (0-100) that the indicator is malicious.",
    )
    mandiant_confidence_score: int | None = Field(
        None,
        description="Mandiant confidence score, deprecated by GTI in favour of gti_confidence_score.",
    )
    mandiant_domain_hijack: bool | None = Field(
        None, description="Indicates domain hijack alert."
    )
    mandiant_osint: bool | None = Field(
        None, description="Indicates widespread OSINT reports."
    )
    safebrowsing_verdict: str | None = Field(
        None, description="Google Safe Browsing verdict."
    )
    gavs_detections: int | None = Field(None, description="Number of GAVS detections.")
    gavs_categories: list[str] | None = Field(
        None, description="Threat categories from GAVS."
    )
    normalised_categories: list[str] | None = Field(
        None, description="Normalized threat categories."
    )
    legitimate_software: bool | None = Field(
        None, description="Indicator if file is legitimate."
    )
    matched_malicious_yara: bool | None = Field(
        None, description="Matched malicious YARA rule."
    )
    malicious_sandbox_verdict: bool | None = Field(
        None, description="Detected malicious in sandbox analysis."
    )
    associated_reference: bool | None = Field(
        None, description="Appears in public sources."
    )
    associated_malware_configuration: bool | None = Field(
        None, description="Contains known malware configurations."
    )
    associated_actor: bool | None = Field(
        None, description="Associated with a threat actor."
    )
    high_severity_related_files: bool | None = Field(
        None, description="Related files marked high severity."
    )
    medium_severity_related_files: bool | None = Field(
        None, description="Related files marked medium severity."
    )
    low_severity_related_files: bool | None = Field(
        None, description="Related files marked low severity."
    )
    pervasive_indicator: bool | None = Field(
        None, description="Related files seen in OSINT."
    )
    # Domain-only signals.
    mandiant_malware_analysis_1: bool | None = Field(
        None, description="Google TI malware analysis detection."
    )
    mandiant_malware_analysis_2: bool | None = Field(
        None, description="Additional Google TI malware analysis detection."
    )
    mandiant_malware_analysis_3: bool | None = Field(
        None, description="Additional Google TI malware analysis detection."
    )
    mandiant_botnet_emulation: bool | None = Field(
        None, description="Indicator from GTI botnet emulation."
    )
    mandiant_mobile_malware_analysis: bool | None = Field(
        None, description="Indicator from GTI mobile malware analysis."
    )
    mandiant_malware_similarity: bool | None = Field(
        None, description="Indicator from GTI malware similarity analysis."
    )
    mandiant_malware_analysis_auto: bool | None = Field(
        None, description="Indicator from GTI automated malware analysis."
    )


class DescriptionCardTarget(BaseModel):
    """GTI object a description card links to."""

    object_type: str | None = Field(
        None, description="GTI object type (e.g., 'collection', 'file')."
    )
    id: str | None = Field(None, description="GTI object identifier.")


class DescriptionCardLink(BaseModel):
    """Link from a description card to a related GTI object."""

    title: str | None = Field(None, description="Display text of the link.")
    url: DescriptionCardTarget | None = Field(None, description="Link target.")


class DescriptionCard(BaseModel):
    """GTI explanation card for one factor of the verdict."""

    influence: str | None = Field(
        None, description="Influence on the verdict: high, medium, low or benign."
    )
    title: str | None = Field(None, description="Factor summary.")
    sub_title: str | None = Field(None, description="Factor details, may be empty.")
    collection_type: str | None = Field(
        None, description="Related collection type (e.g., 'threat-actor')."
    )
    related_links: list[DescriptionCardLink] | None = Field(
        None, description="Related GTI objects."
    )


class GTIAssessment(BaseModel):
    """GTI assessment of an IOC."""

    verdict: Verdict | None = Field(None, description="Verdict of the GTI assessment.")
    severity: Severity | None = Field(
        None, description="Severity of the GTI assessment."
    )
    threat_score: ThreatScore | None = Field(
        None, description="Threat score from GTI assessment."
    )
    contributing_factors: ContributingFactors | None = Field(
        None, description="Signals contributing to the verdict and severity."
    )
    description: str | None = Field(
        None, description="Human-readable description of the assessment factors."
    )
    gti_description_cards: dict[str, list[DescriptionCard]] | None = Field(
        None,
        description="Explanation cards by category (e.g., 'HIGHEST_IMPACT_FACTOR').",
    )


class LastAnalysisStats(BaseModel):
    """Summary statistics for the latest scan results."""

    confirmed_timeout: int | None = Field(
        None, description="Count of confirmed timeouts."
    )
    failure: int | None = Field(None, description="Count of scan failures.")
    harmless: int | None = Field(None, description="Count marking harmless.")
    malicious: int | None = Field(None, description="Count marking malicious.")
    suspicious: int | None = Field(None, description="Count marking suspicious.")
    timeout: int | None = Field(None, description="Count of timeouts.")
    type_unsupported: int | None = Field(
        None, description="Count of unsupported file types."
    )
    undetected: int | None = Field(None, description="Count marking undetected.")
