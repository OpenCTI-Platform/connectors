"""Module containing models for GTI IPaddresses response from Google Threat Intelligence API."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Verdict(BaseModel):
    """Model representing a GTI assessment verdict."""

    value: Optional[str] = Field(
        None, description="Verdict value (e.g., 'VERDICT_BENIGN')."
    )


class Severity(BaseModel):
    """Model representing a GTI assessment severity."""

    value: Optional[str] = Field(
        None, description="Severity value (e.g., 'SEVERITY_LOW')."
    )


class ThreatScore(BaseModel):
    """Model representing the GTI threat score."""

    value: Optional[int] = Field(
        None, description="Threat score, integer between 0 and 100."
    )


class ContributingFactors(BaseModel):
    """Model representing factors contributing to GTI assessment."""

    mandiant_analyst_benign: Optional[bool] = Field(
        None, description="Indicator if a GTI analyst determined it benign."
    )
    mandiant_analyst_malicious: Optional[bool] = Field(
        None, description="Indicator if a GTI analyst determined it malicious."
    )
    google_malware_analysis: Optional[bool] = Field(
        None, description="Detected by GTI malware analysis."
    )
    google_botnet_emulation: Optional[bool] = Field(
        None, description="Detected by GTI botnet emulation."
    )
    google_mobile_malware_analysis: Optional[bool] = Field(
        None, description="Detected by GTI mobile malware analysis."
    )
    google_malware_similarity: Optional[bool] = Field(
        None, description="Detected by GTI malware similarity analysis."
    )
    google_malware_analysis_auto: Optional[bool] = Field(
        None, description="Detected by GTI automated malware analysis."
    )
    mandiant_association_report: Optional[bool] = Field(
        None, description="Associated with a GTI intelligence report."
    )
    mandiant_association_actor: Optional[bool] = Field(
        None, description="Associated with a tracked GTI threat actor."
    )
    mandiant_association_malware: Optional[bool] = Field(
        None, description="Associated with a tracked GTI malware family."
    )
    mandiant_confidence_score: Optional[int] = Field(
        None, description="GTI confidence score for the indicator."
    )
    mandiant_domain_hijack: Optional[bool] = Field(
        None, description="Domain hijack indicator from GTI."
    )
    mandiant_osint: Optional[bool] = Field(
        None, description="Considered widespread in OSINT sources."
    )
    safebrowsing_verdict: Optional[bool] = Field(
        None, description="Google Safe Browsing verdict."
    )
    gavs_detections: Optional[int] = Field(
        None,
        description="Number of detections by Google’s spam and threat filtering engines.",
    )
    gavs_categories: Optional[List[str]] = Field(
        None, description="Known threat categories from GAVS."
    )
    normalised_categories: Optional[List[str]] = Field(
        None, description="Normalized threat categories."
    )
    legitimate_software: Optional[bool] = Field(
        None, description="Indicator if associated with trusted software."
    )
    matched_malicious_yara: Optional[bool] = Field(
        None, description="Matches malicious YARA rules."
    )
    malicious_sandbox_verdict: Optional[bool] = Field(
        None, description="Detected by sandbox analysis."
    )
    associated_reference: Optional[bool] = Field(
        None, description="Appears in public sources."
    )
    associated_malware_configuration: Optional[bool] = Field(
        None, description="Contains known malware configurations."
    )
    associated_actor: Optional[bool] = Field(
        None, description="Associated with a community threat actor."
    )
    high_severity_related_files: Optional[bool] = Field(
        None, description="Related files marked as high severity malicious."
    )
    medium_severity_related_files: Optional[bool] = Field(
        None, description="Related files marked as medium severity malicious."
    )
    low_severity_related_files: Optional[bool] = Field(
        None, description="Related files marked as low severity malicious."
    )
    pervasive_indicator: Optional[bool] = Field(
        None, description="Related files seen in OSINT sources."
    )


class GTIAssessment(BaseModel):
    """Model representing a GTI assessment for an IP."""

    verdict: Optional[Verdict] = Field(
        None, description="Verdict of the GTI assessment."
    )
    severity: Optional[Severity] = Field(
        None, description="Severity of the GTI assessment."
    )
    threat_score: Optional[ThreatScore] = Field(
        None, description="Threat score from GTI assessment."
    )
    description: Optional[str] = Field(
        None, description="Human-readable description of assessment factors."
    )
    contributing_factors: Optional[ContributingFactors] = Field(
        None, description="Signals contributing to the verdict and severity."
    )


class LastAnalysisResult(BaseModel):
    """Model representing results from a single IP scanner."""

    category: Optional[str] = Field(
        None, description="Normalized category (e.g., 'harmless', 'malicious')."
    )
    engine_name: Optional[str] = Field(
        None, description="Complete name of the scanning engine."
    )
    method: Optional[str] = Field(
        None, description="Type of service provided by the scanner (e.g., 'blacklist')."
    )
    result: Optional[str] = Field(
        None, description="Raw result from the scanner (e.g., 'clean', 'phishing')."
    )


class LastAnalysisStats(BaseModel):
    """Model representing aggregated analysis statistics for an IP."""

    harmless: Optional[int] = Field(
        None, description="Number of reports marking harmless."
    )
    malicious: Optional[int] = Field(
        None, description="Number of reports marking malicious."
    )
    suspicious: Optional[int] = Field(
        None, description="Number of reports marking suspicious."
    )
    timeout: Optional[int] = Field(
        None, description="Number of timeouts during scanning."
    )
    undetected: Optional[int] = Field(
        None, description="Number of reports marking undetected."
    )


class TotalVotes(BaseModel):
    """Model representing total community votes for an IP."""

    harmless: Optional[int] = Field(
        None, description="Number of votes marking harmless."
    )
    malicious: Optional[int] = Field(
        None, description="Number of votes marking malicious."
    )


class IPModel(BaseModel):
    """Model representing attributes of an IP object."""

    as_owner: Optional[str] = Field(None, description="Owner of the Autonomous System.")
    asn: Optional[int] = Field(None, description="Autonomous System Number.")
    continent: Optional[str] = Field(None, description="Continent code (ISO-3166).")
    country: Optional[str] = Field(None, description="Country code (ISO-3166).")
    gti_assessment: Optional[GTIAssessment] = Field(
        None, description="Google Threat Intelligence assessment for the IP."
    )
    jarm: Optional[str] = Field(None, description="JARM hash of the IP.")
    last_analysis_date: Optional[int] = Field(
        None, description="Timestamp of last IP scan (UTC)."
    )
    last_analysis_results: Optional[Dict[str, LastAnalysisResult]] = Field(
        None, description="Results from individual IP scanners."
    )
    last_analysis_stats: Optional[LastAnalysisStats] = Field(
        None, description="Aggregated analysis statistics."
    )
    last_modification_date: Optional[int] = Field(
        None, description="Timestamp when IP information was last modified (UTC)."
    )
    network: Optional[str] = Field(
        None, description="IPv4 network range to which the IP belongs."
    )
    regional_internet_registry: Optional[str] = Field(
        None, description="Regional Internet Registry (e.g., 'ARIN')."
    )
    reputation: Optional[int] = Field(
        None, description="Community-calculated reputation score."
    )
    tags: Optional[List[str]] = Field(
        None, description="List of tags associated with the IP."
    )
    total_votes: Optional[TotalVotes] = Field(
        None, description="Community vote breakdown for the IP."
    )
    whois: Optional[str] = Field(None, description="WHOIS information for the IP.")
    whois_date: Optional[int] = Field(
        None, description="Timestamp of last WHOIS record update (UTC)."
    )


class GTIIPData(BaseModel):
    """Model representing the 'data' section for an IP object."""

    id: str = Field(..., description="IP address identifier.")
    type: str = Field("ip_address", description="Resource type, set to 'ip_address'.")
    links: Optional[Dict[str, str]] = Field(
        None, description="Links related to the IP resource."
    )
    attributes: Optional[IPModel] = Field(
        None, description="Attributes of the IP resource."
    )


class GTIIPResponse(BaseModel):
    """Model representing a response containing IP data."""

    data: GTIIPData
