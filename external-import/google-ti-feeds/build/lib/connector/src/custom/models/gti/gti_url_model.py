"""Module containing models for GTI URL response from Google Threat Intelligence API."""

from typing import Any

from pydantic import BaseModel, Field


class Favicon(BaseModel):
    """Model representing a URL's favicon hashes."""

    dhash: str | None = Field(None, description="Difference hash of the favicon.")
    raw_md5: str | None = Field(None, description="MD5 hash of the favicon.")


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
    safebrowsing_verdict: str | None = Field(
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
    """Model representing a GTI assessment for a URL."""

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
    """Model representing results from a single URL scanner."""

    category: str | None = Field(
        None, description="Normalized category (e.g., 'harmless', 'malicious')."
    )
    engine_name: str | None = Field(
        None, description="Complete name of the scanning engine."
    )
    method: str | None = Field(
        None,
        description="Type of service provided by the URL scanner (e.g., 'blacklist').",
    )
    result: str | None = Field(
        None, description="Raw result from the URL scanner (e.g., 'clean', 'phishing')."
    )


class LastAnalysisStats(BaseModel):
    """Model representing aggregated analysis statistics."""

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


class Tracker(BaseModel):
    """Model representing a single tracker entry for a URL."""

    id: str | None = Field(None, description="Tracker ID if available.")
    timestamp: int | None = Field(
        None, description="Tracker ingestion date as UNIX timestamp."
    )
    url: str | None = Field(None, description="Tracker script URL.")


class URLModel(BaseModel):
    """Model representing attributes of a URL object."""

    categories: dict[str, str] | None = Field(
        None, description="Mapping of categorization services to assigned category."
    )
    favicon: Favicon | None = Field(
        None, description="Favicon hash information (premium only)."
    )
    first_submission_date: int | None = Field(
        None, description="Timestamp when URL was first submitted (UTC)."
    )
    gti_assessment: GTIAssessment | None = Field(
        None, description="Google Threat Intelligence assessment for the URL."
    )
    html_meta: dict[str, list[str]] | None = Field(
        None,
        description="All meta tags from HTML; keys are tag names and values lists of tag content.",
    )
    last_analysis_date: int | None = Field(
        None, description="Timestamp of last URL scan (UTC)."
    )
    last_analysis_results: dict[str, LastAnalysisResult] | None = Field(
        None, description="Results from individual URL scanners."
    )
    last_analysis_stats: LastAnalysisStats | None = Field(
        None, description="Aggregated analysis statistics."
    )
    last_final_url: str | None = Field(
        None, description="Final URL after following redirects."
    )
    last_http_response_code: int | None = Field(
        None, description="HTTP response code of the last response."
    )
    last_http_response_content_length: int | None = Field(
        None, description="Content length in bytes of the last HTTP response."
    )
    last_http_response_content_sha256: str | None = Field(
        None, description="SHA256 hash of the last HTTP response content."
    )
    last_http_response_cookies: dict[str, str] | None = Field(
        None, description="Cookies from the last HTTP response."
    )
    last_http_response_headers: dict[str, str] | None = Field(
        None, description="Headers from the last HTTP response."
    )
    last_modification_date: int | None = Field(
        None, description="Timestamp of last modification (UTC)."
    )
    last_submission_date: int | None = Field(
        None, description="Timestamp of last submission for analysis (UTC)."
    )
    outgoing_links: list[str] | None = Field(
        None, description="Links to different domains extracted from the URL."
    )
    redirection_chain: list[str] | None = Field(
        None, description="Redirection history (excluding final URL)."
    )
    reputation: int | None = Field(
        None, description="Community-calculated reputation score."
    )
    tags: list[str] | None = Field(
        None, description="list of tags associated with the URL."
    )
    targeted_brand: dict[str, Any] | None = Field(
        None, description="Targeted brand information extracted from phishing engines."
    )
    times_submitted: int | None = Field(
        None, description="Number of times the URL has been checked."
    )
    title: str | None = Field(None, description="Webpage title.")
    total_votes: dict[str, int] | None = Field(
        None, description="Community vote breakdown ('harmless' and 'malicious')."
    )
    trackers: dict[str, list[Tracker]] | None = Field(
        None,
        description="Trackers found in the URL; keys are tracker names, values are lists of tracker entries.",
    )
    url: str | None = Field(None, description="Original URL to be scanned.")
    has_content: bool | None = Field(None, description="Whether the URL has content.")


class GTIURLData(BaseModel):
    """Model representing the 'data' section for a URL."""

    id: str = Field(..., description="URL identifier or encoded value.")
    type: str = Field("url", description="Resource type, set to 'url'.")
    links: dict[str, str] | None = Field(
        None, description="Links related to the URL resource."
    )
    attributes: URLModel | None = Field(
        None, description="Attributes of the URL resource."
    )


class GTIURLResponse(BaseModel):
    """Model representing a response containing URL data."""

    data: GTIURLData
