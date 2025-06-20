"""Module containing models for GTI domain response from Google Threat Intelligence API."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Favicon(BaseModel):
    """Model representing a domain's favicon hashes."""

    dhash: Optional[str] = Field(None, description="Difference hash of the favicon.")
    raw_md5: Optional[str] = Field(None, description="MD5 hash of the favicon.")


class Verdict(BaseModel):
    """Model representing a GTI assessment verdict."""

    value: Optional[str] = Field(
        None, description="Verdict value (e.g., 'VERDICT_BENIGN', 'VERDICT_MALICIOUS')."
    )


class Severity(BaseModel):
    """Model representing a GTI assessment severity."""

    value: Optional[str] = Field(
        None, description="Severity value (e.g., 'SEVERITY_LOW', 'SEVERITY_HIGH')."
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
    mandiant_malware_analysis_1: Optional[bool] = Field(
        None, description="Google TI malware analysis detection."
    )
    mandiant_malware_analysis_2: Optional[bool] = Field(
        None, description="Additional Google TI malware analysis detection."
    )
    mandiant_malware_analysis_3: Optional[bool] = Field(
        None, description="Additional Google TI malware analysis detection."
    )
    mandiant_botnet_emulation: Optional[bool] = Field(
        None, description="Indicator from GTI botnet emulation."
    )
    mandiant_mobile_malware_analysis: Optional[bool] = Field(
        None, description="Indicator from GTI mobile malware analysis."
    )
    mandiant_malware_similarity: Optional[bool] = Field(
        None, description="Indicator from GTI malware similarity analysis."
    )
    mandiant_malware_analysis_auto: Optional[bool] = Field(
        None, description="Indicator from GTI automated malware analysis."
    )
    mandiant_association_report: Optional[bool] = Field(
        None, description="Indicator if associated with a GTI intelligence report."
    )
    mandiant_association_actor: Optional[bool] = Field(
        None, description="Indicator if associated with a tracked GTI threat actor."
    )
    mandiant_association_malware: Optional[bool] = Field(
        None, description="Indicator if associated with a tracked GTI malware family."
    )
    mandiant_confidence_score: Optional[int] = Field(
        None, description="GTI confidence score for the indicator."
    )
    mandiant_domain_hijack: Optional[bool] = Field(
        None, description="Indicator if the domain was hijacked per GTI."
    )
    mandiant_osint: Optional[bool] = Field(
        None, description="Indicator if considered widespread in OSINT sources."
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
        None, description="Indicator if matches malicious YARA rules."
    )
    malicious_sandbox_verdict: Optional[bool] = Field(
        None, description="Indicator if detected by sandbox analysis."
    )
    associated_reference: Optional[bool] = Field(
        None, description="Indicator if appears in public sources."
    )
    associated_malware_configuration: Optional[bool] = Field(
        None, description="Indicator if contains known malware configurations."
    )
    associated_actor: Optional[bool] = Field(
        None, description="Indicator if associated with a community threat actor."
    )
    high_severity_related_files: Optional[bool] = Field(
        None,
        description="Indicator if related files are marked as high severity malicious.",
    )
    medium_severity_related_files: Optional[bool] = Field(
        None,
        description="Indicator if related files are marked as medium severity malicious.",
    )
    low_severity_related_files: Optional[bool] = Field(
        None,
        description="Indicator if related files are marked as low severity malicious.",
    )
    pervasive_indicator: Optional[bool] = Field(
        None, description="Indicator if related files seen in OSINT sources."
    )


class GTIAssessment(BaseModel):
    """Model representing a GTI assessment for a domain."""

    verdict: Optional[Verdict] = Field(
        None, description="Verdict of the GTI assessment."
    )
    severity: Optional[Severity] = Field(
        None, description="Severity of the GTI assessment."
    )
    threat_score: Optional[ThreatScore] = Field(
        None, description="Threat score from GTI assessment."
    )
    contributing_factors: Optional[ContributingFactors] = Field(
        None, description="Signals contributing to the verdict and severity."
    )
    description: Optional[str] = Field(
        None, description="Human-readable description of the assessment factors."
    )


class LastAnalysisResult(BaseModel):
    """Model representing results from a single URL scanner."""

    category: Optional[str] = Field(
        None, description="Normalized category (e.g., 'harmless', 'malicious')."
    )
    engine_name: Optional[str] = Field(
        None, description="Complete name of the scanning engine."
    )
    engine_version: Optional[str] = Field(
        None, description="Version of the scanning engine."
    )
    method: Optional[str] = Field(
        None,
        description="Type of service provided by the URL scanner (e.g., 'blacklist').",
    )
    result: Optional[str] = Field(
        None, description="Raw result from the URL scanner (e.g., 'clean', 'phishing')."
    )


class LastAnalysisStats(BaseModel):
    """Model representing aggregated analysis statistics."""

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


class LastDnsRecord(BaseModel):
    """Model representing a single DNS record."""

    expire: Optional[int] = Field(None, description="Expire field of the DNS record.")
    flag: Optional[int] = Field(None, description="Flag field of the DNS record.")
    minimum: Optional[int] = Field(None, description="Minimum TTL of the DNS record.")
    priority: Optional[int] = Field(None, description="Priority of the DNS record.")
    refresh: Optional[int] = Field(None, description="Refresh field of the DNS record.")
    rname: Optional[str] = Field(
        None, description="Responsible party for the DNS record."
    )
    retry: Optional[int] = Field(None, description="Retry field of the DNS record.")
    serial: Optional[int] = Field(None, description="Serial number of the DNS record.")
    tag: Optional[str] = Field(None, description="Tag of the DNS record.")
    ttl: Optional[int] = Field(None, description="Time-to-live of the DNS record.")
    type: Optional[str] = Field(
        None, description="Type of the DNS record (e.g., 'A', 'MX')."
    )
    value: Optional[str] = Field(None, description="Value of the DNS record.")


class PopularityRank(BaseModel):
    """Model representing a domain's rank in a popularity service."""

    rank: Optional[int] = Field(None, description="Rank position.")
    timestamp: Optional[int] = Field(
        None, description="Timestamp when the rank was recorded (UTC). "
    )


class TotalVotes(BaseModel):
    """Model representing total community votes."""

    harmless: Optional[int] = Field(
        None, description="Number of votes marking harmless."
    )
    malicious: Optional[int] = Field(
        None, description="Number of votes marking malicious."
    )


class DomainModel(BaseModel):
    """Model representing attributes of a domain object."""

    categories: Optional[Dict[str, str]] = Field(
        None, description="Mapping of categorization services to assigned category."
    )
    creation_date: Optional[int] = Field(
        None, description="Creation date from WHOIS (UTC timestamp)."
    )
    favicon: Optional[Favicon] = Field(
        None, description="Favicon hash information (premium only)."
    )
    gti_assessment: Optional[GTIAssessment] = Field(
        None, description="Google Threat Intelligence assessment for the domain."
    )
    jarm: Optional[str] = Field(None, description="JARM hash of the domain.")
    last_analysis_date: Optional[int] = Field(
        None, description="Timestamp of last domain scan (UTC)."
    )
    last_analysis_results: Optional[Dict[str, LastAnalysisResult]] = Field(
        None, description="Results from individual URL scanners."
    )
    last_analysis_stats: Optional[LastAnalysisStats] = Field(
        None, description="Aggregated analysis statistics."
    )
    last_dns_records: Optional[List[LastDnsRecord]] = Field(
        None, description="List of DNS records from last scan."
    )
    last_dns_records_date: Optional[int] = Field(
        None, description="Timestamp when DNS records were retrieved (UTC)."
    )
    last_https_certificate: Optional[Dict[str, Any]] = Field(
        None, description="SSL Certificate object from last analysis."
    )
    last_https_certificate_date: Optional[int] = Field(
        None, description="Timestamp when the HTTPS certificate was retrieved (UTC)."
    )
    last_modification_date: Optional[int] = Field(
        None, description="Timestamp when domain information was last modified (UTC)."
    )
    last_update_date: Optional[int] = Field(
        None, description="Timestamp from WHOIS last update (UTC)."
    )
    popularity_ranks: Optional[Dict[str, PopularityRank]] = Field(
        None, description="Domain's rank positions in popularity services."
    )
    registrar: Optional[str] = Field(
        None, description="Registrar company of the domain."
    )
    reputation: Optional[int] = Field(
        None, description="Community-calculated reputation score."
    )
    tags: Optional[List[str]] = Field(
        None, description="List of representative tags for the domain."
    )
    total_votes: Optional[TotalVotes] = Field(
        None, description="Community vote breakdown for the domain."
    )
    whois: Optional[str] = Field(
        None, description="WHOIS information as returned by the WHOIS server."
    )
    whois_date: Optional[int] = Field(
        None, description="Timestamp of last WHOIS record update (UTC)."
    )


class GTIDomainData(BaseModel):
    """Model representing the 'data' section for a domain."""

    id: str = Field(..., description="Domain name or identifier.")
    type: str = Field("domain", description="Resource type, set to 'domain'.")
    links: Optional[Dict[str, str]] = Field(
        None, description="Links related to the domain resource."
    )
    attributes: Optional[DomainModel] = Field(
        None, description="Attributes of the domain resource."
    )


class GTIDomainResponse(BaseModel):
    """Model representing a response containing domain data."""

    data: GTIDomainData
