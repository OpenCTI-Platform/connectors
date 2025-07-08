"""Module containing models for GTI URL response from Google Threat Intelligence API."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Favicon(BaseModel):
    """Model representing a URL's favicon hashes."""

    dhash: Optional[str] = Field(None, description="Difference hash of the favicon.")
    raw_md5: Optional[str] = Field(None, description="MD5 hash of the favicon.")


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
    """Model representing a GTI assessment for a URL."""

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
    """Model representing results from a single URL scanner."""

    category: Optional[str] = Field(
        None, description="Normalized category (e.g., 'harmless', 'malicious')."
    )
    engine_name: Optional[str] = Field(
        None, description="Complete name of the scanning engine."
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


class Tracker(BaseModel):
    """Model representing a single tracker entry for a URL."""

    id: Optional[str] = Field(None, description="Tracker ID if available.")
    timestamp: Optional[int] = Field(
        None, description="Tracker ingestion date as UNIX timestamp."
    )
    url: Optional[str] = Field(None, description="Tracker script URL.")


class URLModel(BaseModel):
    """Model representing attributes of a URL object."""

    categories: Optional[Dict[str, str]] = Field(
        None, description="Mapping of categorization services to assigned category."
    )
    favicon: Optional[Favicon] = Field(
        None, description="Favicon hash information (premium only)."
    )
    first_submission_date: Optional[int] = Field(
        None, description="Timestamp when URL was first submitted (UTC)."
    )
    gti_assessment: Optional[GTIAssessment] = Field(
        None, description="Google Threat Intelligence assessment for the URL."
    )
    html_meta: Optional[Dict[str, List[str]]] = Field(
        None,
        description="All meta tags from HTML; keys are tag names and values lists of tag content.",
    )
    last_analysis_date: Optional[int] = Field(
        None, description="Timestamp of last URL scan (UTC)."
    )
    last_analysis_results: Optional[Dict[str, LastAnalysisResult]] = Field(
        None, description="Results from individual URL scanners."
    )
    last_analysis_stats: Optional[LastAnalysisStats] = Field(
        None, description="Aggregated analysis statistics."
    )
    last_final_url: Optional[str] = Field(
        None, description="Final URL after following redirects."
    )
    last_http_response_code: Optional[int] = Field(
        None, description="HTTP response code of the last response."
    )
    last_http_response_content_length: Optional[int] = Field(
        None, description="Content length in bytes of the last HTTP response."
    )
    last_http_response_content_sha256: Optional[str] = Field(
        None, description="SHA256 hash of the last HTTP response content."
    )
    last_http_response_cookies: Optional[Dict[str, str]] = Field(
        None, description="Cookies from the last HTTP response."
    )
    last_http_response_headers: Optional[Dict[str, str]] = Field(
        None, description="Headers from the last HTTP response."
    )
    last_modification_date: Optional[int] = Field(
        None, description="Timestamp of last modification (UTC)."
    )
    last_submission_date: Optional[int] = Field(
        None, description="Timestamp of last submission for analysis (UTC)."
    )
    outgoing_links: Optional[List[str]] = Field(
        None, description="Links to different domains extracted from the URL."
    )
    redirection_chain: Optional[List[str]] = Field(
        None, description="Redirection history (excluding final URL)."
    )
    reputation: Optional[int] = Field(
        None, description="Community-calculated reputation score."
    )
    tags: Optional[List[str]] = Field(
        None, description="List of tags associated with the URL."
    )
    targeted_brand: Optional[Dict[str, Any]] = Field(
        None, description="Targeted brand information extracted from phishing engines."
    )
    times_submitted: Optional[int] = Field(
        None, description="Number of times the URL has been checked."
    )
    title: Optional[str] = Field(None, description="Webpage title.")
    total_votes: Optional[Dict[str, int]] = Field(
        None, description="Community vote breakdown ('harmless' and 'malicious')."
    )
    trackers: Optional[Dict[str, List[Tracker]]] = Field(
        None,
        description="Trackers found in the URL; keys are tracker names, values are lists of tracker entries.",
    )
    url: Optional[str] = Field(None, description="Original URL to be scanned.")
    has_content: Optional[bool] = Field(
        None, description="Whether the URL has content."
    )


class GTIURLData(BaseModel):
    """Model representing the 'data' section for a URL."""

    id: str = Field(..., description="URL identifier or encoded value.")
    type: str = Field("url", description="Resource type, set to 'url'.")
    links: Optional[Dict[str, str]] = Field(
        None, description="Links related to the URL resource."
    )
    attributes: Optional[URLModel] = Field(
        None, description="Attributes of the URL resource."
    )


class GTIURLResponse(BaseModel):
    """Model representing a response containing URL data."""

    data: GTIURLData
