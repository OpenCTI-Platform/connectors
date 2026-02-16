"""Module containing models for GTI IPaddresses response from Google Threat Intelligence API."""

from pydantic import BaseModel, Field


class Verdict(BaseModel):
    """Model representing a GTI assessment verdict."""

    value: str | None = Field(
        None, description="Verdict value (e.g., 'VERDICT_BENIGN')."
    )


class Severity(BaseModel):
    """Model representing a GTI assessment severity."""

    value: str | None = Field(
        None, description="Severity value (e.g., 'SEVERITY_LOW')."
    )


class ThreatScore(BaseModel):
    """Model representing the GTI threat score."""

    value: int | None = Field(
        None, description="Threat score, integer between 0 and 100."
    )


class ContributingFactors(BaseModel):
    """Model representing factors contributing to GTI assessment."""

    mandiant_analyst_benign: bool | None = Field(
        None, description="Indicator if a GTI analyst determined it benign."
    )
    mandiant_analyst_malicious: bool | None = Field(
        None, description="Indicator if a GTI analyst determined it malicious."
    )
    google_malware_analysis: bool | None = Field(
        None, description="Detected by GTI malware analysis."
    )
    google_botnet_emulation: bool | None = Field(
        None, description="Detected by GTI botnet emulation."
    )
    google_mobile_malware_analysis: bool | None = Field(
        None, description="Detected by GTI mobile malware analysis."
    )
    google_malware_similarity: bool | None = Field(
        None, description="Detected by GTI malware similarity analysis."
    )
    google_malware_analysis_auto: bool | None = Field(
        None, description="Detected by GTI automated malware analysis."
    )
    mandiant_association_report: bool | None = Field(
        None, description="Associated with a GTI intelligence report."
    )
    mandiant_association_actor: bool | None = Field(
        None, description="Associated with a tracked GTI threat actor."
    )
    mandiant_association_malware: bool | None = Field(
        None, description="Associated with a tracked GTI malware family."
    )
    mandiant_confidence_score: int | None = Field(
        None, description="GTI confidence score for the indicator."
    )
    mandiant_domain_hijack: bool | None = Field(
        None, description="Domain hijack indicator from GTI."
    )
    mandiant_osint: bool | None = Field(
        None, description="Considered widespread in OSINT sources."
    )
    safebrowsing_verdict: bool | None = Field(
        None, description="Google Safe Browsing verdict."
    )
    gavs_detections: int | None = Field(
        None,
        description="Number of detections by Google's spam and threat filtering engines.",
    )
    gavs_categories: list[str] | None = Field(
        None, description="Known threat categories from GAVS."
    )
    normalised_categories: list[str] | None = Field(
        None, description="Normalized threat categories."
    )
    legitimate_software: bool | None = Field(
        None, description="Indicator if associated with trusted software."
    )
    matched_malicious_yara: bool | None = Field(
        None, description="Matches malicious YARA rules."
    )
    malicious_sandbox_verdict: bool | None = Field(
        None, description="Detected by sandbox analysis."
    )
    associated_reference: bool | None = Field(
        None, description="Appears in public sources."
    )
    associated_malware_configuration: bool | None = Field(
        None, description="Contains known malware configurations."
    )
    associated_actor: bool | None = Field(
        None, description="Associated with a community threat actor."
    )
    high_severity_related_files: bool | None = Field(
        None, description="Related files marked as high severity malicious."
    )
    medium_severity_related_files: bool | None = Field(
        None, description="Related files marked as medium severity malicious."
    )
    low_severity_related_files: bool | None = Field(
        None, description="Related files marked as low severity malicious."
    )
    pervasive_indicator: bool | None = Field(
        None, description="Related files seen in OSINT sources."
    )


class GTIAssessment(BaseModel):
    """Model representing a GTI assessment for an IP."""

    verdict: Verdict | None = Field(None, description="Verdict of the GTI assessment.")
    severity: Severity | None = Field(
        None, description="Severity of the GTI assessment."
    )
    threat_score: ThreatScore | None = Field(
        None, description="Threat score from GTI assessment."
    )
    description: str | None = Field(
        None, description="Human-readable description of assessment factors."
    )
    contributing_factors: ContributingFactors | None = Field(
        None, description="Signals contributing to the verdict and severity."
    )


class LastAnalysisResult(BaseModel):
    """Model representing results from a single IP scanner."""

    category: str | None = Field(
        None, description="Normalized category (e.g., 'harmless', 'malicious')."
    )
    engine_name: str | None = Field(
        None, description="Complete name of the scanning engine."
    )
    method: str | None = Field(
        None, description="Type of service provided by the scanner (e.g., 'blacklist')."
    )
    result: str | None = Field(
        None, description="Raw result from the scanner (e.g., 'clean', 'phishing')."
    )


class LastAnalysisStats(BaseModel):
    """Model representing aggregated analysis statistics for an IP."""

    harmless: int | None = Field(
        None, description="Number of reports marking harmless."
    )
    malicious: int | None = Field(
        None, description="Number of reports marking malicious."
    )
    suspicious: int | None = Field(
        None, description="Number of reports marking suspicious."
    )
    timeout: int | None = Field(None, description="Number of timeouts during scanning.")
    undetected: int | None = Field(
        None, description="Number of reports marking undetected."
    )


class TotalVotes(BaseModel):
    """Model representing total community votes for an IP."""

    harmless: int | None = Field(None, description="Number of votes marking harmless.")
    malicious: int | None = Field(
        None, description="Number of votes marking malicious."
    )


class IPModel(BaseModel):
    """Model representing attributes of an IP object."""

    as_owner: str | None = Field(None, description="Owner of the Autonomous System.")
    asn: int | None = Field(None, description="Autonomous System Number.")
    continent: str | None = Field(None, description="Continent code (ISO-3166).")
    country: str | None = Field(None, description="Country code (ISO-3166).")
    gti_assessment: GTIAssessment | None = Field(
        None, description="Google Threat Intelligence assessment for the IP."
    )
    jarm: str | None = Field(None, description="JARM hash of the IP.")
    last_analysis_date: int | None = Field(
        None, description="Timestamp of last IP scan (UTC)."
    )
    last_analysis_results: dict[str, LastAnalysisResult] | None = Field(
        None, description="Results from individual IP scanners."
    )
    last_analysis_stats: LastAnalysisStats | None = Field(
        None, description="Aggregated analysis statistics."
    )
    last_modification_date: int | None = Field(
        None, description="Timestamp when IP information was last modified (UTC)."
    )
    network: str | None = Field(
        None, description="IPv4 network range to which the IP belongs."
    )
    regional_internet_registry: str | None = Field(
        None, description="Regional Internet Registry (e.g., 'ARIN')."
    )
    reputation: int | None = Field(
        None, description="Community-calculated reputation score."
    )
    tags: list[str] | None = Field(
        None, description="list of tags associated with the IP."
    )
    total_votes: TotalVotes | None = Field(
        None, description="Community vote breakdown for the IP."
    )
    whois: str | None = Field(None, description="WHOIS information for the IP.")
    whois_date: int | None = Field(
        None, description="Timestamp of last WHOIS record update (UTC)."
    )


class GTIIPData(BaseModel):
    """Model representing the 'data' section for an IP object."""

    id: str = Field(..., description="IP address identifier.")
    type: str = Field("ip_address", description="Resource type, set to 'ip_address'.")
    links: dict[str, str] | None = Field(
        None, description="Links related to the IP resource."
    )
    attributes: IPModel | None = Field(
        None, description="Attributes of the IP resource."
    )


class GTIIPResponse(BaseModel):
    """Model representing a response containing IP data."""

    data: GTIIPData
