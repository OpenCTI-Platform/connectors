"""Module containing models for GTI File response from Google Threat Intelligence API."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class CrowdsourcedAlertContext(BaseModel):
    """Context for a single IDS alert."""

    dest_ip: Optional[str] = Field(None, description="Destination IP of the alert.")
    dest_port: Optional[int] = Field(None, description="Destination port of the alert.")
    hostname: Optional[str] = Field(None, description="Hostname involved in the alert.")
    protocol: Optional[str] = Field(None, description="Protocol used in the alert.")
    src_ip: Optional[str] = Field(None, description="Source IP of the alert.")
    src_port: Optional[int] = Field(None, description="Source port of the alert.")
    url: Optional[str] = Field(None, description="URL involved in the alert.")


class CrowdsourcedIDsResult(BaseModel):
    """Model representing a crowdsourced IDS detection."""

    alert_context: Optional[List[CrowdsourcedAlertContext]] = Field(
        None, description="List of contexts where the IDS triggered."
    )
    alert_severity: Optional[str] = Field(
        None, description="Severity of the IDS alert."
    )
    rule_category: Optional[str] = Field(None, description="Category of the IDS rule.")
    rule_id: Optional[str] = Field(None, description="Identifier for the IDS rule.")
    rule_msg: Optional[str] = Field(None, description="Message for the IDS rule.")
    rule_source: Optional[str] = Field(None, description="Source of the IDS rule.")


class CrowdsourcedIDsStats(BaseModel):
    """Statistics for crowdsourced IDS results."""

    info: Optional[int] = Field(None, description="Count of info-level alerts.")
    high: Optional[int] = Field(None, description="Count of high-severity alerts.")
    low: Optional[int] = Field(None, description="Count of low-severity alerts.")
    medium: Optional[int] = Field(None, description="Count of medium-severity alerts.")


class CrowdsourcedYaraResult(BaseModel):
    """Model representing a crowdsourced YARA match."""

    description: Optional[str] = Field(
        None, description="Description of the YARA match."
    )
    match_in_subfile: Optional[bool] = Field(
        None, description="Whether match was in a subfile."
    )
    rule_name: Optional[str] = Field(None, description="Name of the YARA rule.")
    ruleset_id: Optional[str] = Field(
        None, description="Identifier for the YARA ruleset."
    )
    ruleset_name: Optional[str] = Field(None, description="Name of the YARA ruleset.")
    source: Optional[str] = Field(None, description="Source of the YARA rule.")


class Verdict(BaseModel):
    """Represents a GTI assessment verdict/value."""

    value: Optional[str] = Field(
        None, description="Verdict value (e.g., 'VERDICT_MALICIOUS')."
    )


class Severity(BaseModel):
    """Represents a GTI assessment severity/value."""

    value: Optional[str] = Field(
        None, description="Severity value (e.g., 'SEVERITY_HIGH')."
    )


class ThreatScore(BaseModel):
    """Represents a GTI assessment threat score."""

    value: Optional[int] = Field(None, description="Threat score, 0-100.")


class ContributingFactors(BaseModel):
    """Signals contributing to the GTI assessment."""

    mandiant_analyst_benign: Optional[bool] = Field(
        None, description="Indicator if an analyst marked benign."
    )
    mandiant_analyst_malicious: Optional[bool] = Field(
        None, description="Indicator if an analyst marked malicious."
    )
    google_malware_analysis: Optional[bool] = Field(
        None, description="Detected by Google malware analysis."
    )
    google_botnet_emulation: Optional[bool] = Field(
        None, description="Detected by Google botnet analysis."
    )
    google_mobile_malware_analysis: Optional[bool] = Field(
        None, description="Detected by Google mobile malware analysis."
    )
    google_malware_similarity: Optional[bool] = Field(
        None, description="Detected by Google malware similarity."
    )
    google_malware_analysis_auto: Optional[bool] = Field(
        None, description="Detected by Google automated malware analysis."
    )
    mandiant_association_report: Optional[bool] = Field(
        None, description="Associated with an intelligence report."
    )
    mandiant_association_actor: Optional[bool] = Field(
        None, description="Associated with a threat actor."
    )
    mandiant_association_malware: Optional[bool] = Field(
        None, description="Associated with a malware family."
    )
    mandiant_confidence_score: Optional[int] = Field(
        None, description="GTI confidence score."
    )
    mandiant_domain_hijack: Optional[bool] = Field(
        None, description="Indicates domain hijack alert."
    )
    mandiant_osint: Optional[bool] = Field(
        None, description="Indicates widespread OSINT reports."
    )
    safebrowsing_verdict: Optional[bool] = Field(
        None, description="Google Safe Browsing verdict."
    )
    gavs_detections: Optional[int] = Field(
        None, description="Number of GAVS detections."
    )
    gavs_categories: Optional[List[str]] = Field(
        None, description="Threat categories from GAVS."
    )
    normalised_categories: Optional[List[str]] = Field(
        None, description="Normalized threat categories."
    )
    legitimate_software: Optional[bool] = Field(
        None, description="Indicator if file is legitimate."
    )
    matched_malicious_yara: Optional[bool] = Field(
        None, description="Matched malicious YARA rule."
    )
    malicious_sandbox_verdict: Optional[bool] = Field(
        None, description="Detected malicious in sandbox analysis."
    )
    associated_reference: Optional[bool] = Field(
        None, description="Appears in public sources."
    )
    associated_malware_configuration: Optional[bool] = Field(
        None, description="Contains known malware configurations."
    )
    associated_actor: Optional[bool] = Field(
        None, description="Associated with a threat actor."
    )
    high_severity_related_files: Optional[bool] = Field(
        None, description="Related files marked high severity."
    )
    medium_severity_related_files: Optional[bool] = Field(
        None, description="Related files marked medium severity."
    )
    low_severity_related_files: Optional[bool] = Field(
        None, description="Related files marked low severity."
    )
    pervasive_indicator: Optional[bool] = Field(
        None, description="Related files seen in OSINT."
    )


class GTIAssessment(BaseModel):
    """Google Threat Intelligence assessment for a file."""

    verdict: Optional[Verdict] = Field(
        None, description="Verdict of the GTI assessment."
    )
    severity: Optional[Severity] = Field(
        None, description="Severity level of the GTI assessment."
    )
    threat_score: Optional[ThreatScore] = Field(
        None, description="Threat score from GTI assessment."
    )
    contributing_factors: Optional[ContributingFactors] = Field(
        None, description="Factors contributing to verdict/severity."
    )
    description: Optional[str] = Field(
        None, description="Human-readable description of classification."
    )


class LastAnalysisResult(BaseModel):
    """Result from a single antivirus engine."""

    category: Optional[str] = Field(None, description="Normalized result category.")
    engine_name: Optional[str] = Field(
        None, description="Name of the antivirus engine."
    )
    engine_update: Optional[str] = Field(None, description="Date of the engine update.")
    engine_version: Optional[str] = Field(None, description="Version of the engine.")
    method: Optional[str] = Field(
        None, description="Detection method (e.g., 'blacklist')."
    )
    result: Optional[str] = Field(
        None, description="Raw scan result (e.g., 'clean', 'malicious')."
    )


class LastAnalysisStats(BaseModel):
    """Summary statistics for the latest scan results."""

    confirmed_timeout: Optional[int] = Field(
        None, description="Count of confirmed timeouts."
    )
    failure: Optional[int] = Field(None, description="Count of scan failures.")
    harmless: Optional[int] = Field(None, description="Count marking harmless.")
    malicious: Optional[int] = Field(None, description="Count marking malicious.")
    suspicious: Optional[int] = Field(None, description="Count marking suspicious.")
    timeout: Optional[int] = Field(None, description="Count of timeouts.")
    type_unsupported: Optional[int] = Field(
        None, description="Count of unsupported file types."
    )
    undetected: Optional[int] = Field(None, description="Count marking undetected.")


class SandboxVerdict(BaseModel):
    """Summary of sandbox verdict for a specific sandbox."""

    category: Optional[str] = Field(None, description="Normalized verdict category.")
    confidence: Optional[int] = Field(None, description="Verdict confidence (0-100).")
    malware_classification: Optional[List[str]] = Field(
        None, description="Raw sandbox classifications."
    )
    malware_names: Optional[List[str]] = Field(
        None, description="Detected malware family names."
    )
    sandbox_name: Optional[str] = Field(None, description="Name of the sandbox.")


class SigmaAnalysisResultContext(BaseModel):
    """Context for a matched Sigma rule."""

    values: Optional[Dict[str, str]] = Field(
        None, description="Matched key-value context."
    )


class SigmaAnalysisResult(BaseModel):
    """Detail for a single Sigma analysis rule match."""

    rule_title: Optional[str] = Field(None, description="Title of the Sigma rule.")
    rule_source: Optional[str] = Field(None, description="Source of the Sigma rule.")
    match_context: Optional[List[SigmaAnalysisResultContext]] = Field(
        None, description="Context values for the match."
    )
    rule_level: Optional[str] = Field(
        None, description="Severity level of the Sigma rule."
    )
    rule_description: Optional[str] = Field(
        None, description="Description of the Sigma rule."
    )
    rule_author: Optional[str] = Field(None, description="Author of the Sigma rule.")
    rule_id: Optional[str] = Field(None, description="Identifier of the Sigma rule.")


class SigmaAnalysisStats(BaseModel):
    """Summary stats for Sigma analysis."""

    critical: Optional[int] = Field(None, description="Count of critical matches.")
    high: Optional[int] = Field(None, description="Count of high-severity matches.")
    low: Optional[int] = Field(None, description="Count of low-severity matches.")
    medium: Optional[int] = Field(None, description="Count of medium-severity matches.")


class FileModel(BaseModel):
    """Model representing attributes of a file object."""

    capabilities_tags: Optional[List[str]] = Field(
        None, description="List of capability tags (premium only)."
    )
    creation_date: Optional[int] = Field(
        None, description="File build/compile timestamp (UTC)."
    )
    downloadable: Optional[bool] = Field(
        None, description="Whether the file is downloadable (premium only)."
    )
    first_submission_date: Optional[int] = Field(
        None, description="First submission timestamp (UTC)."
    )
    gti_assessment: Optional[GTIAssessment] = Field(
        None, description="GTI assessment for the file."
    )
    last_analysis_date: Optional[int] = Field(
        None, description="Most recent scan timestamp (UTC)."
    )
    last_analysis_results: Optional[Dict[str, LastAnalysisResult]] = Field(
        None, description="Latest scan results by engine."
    )
    last_analysis_stats: Optional[LastAnalysisStats] = Field(
        None, description="Summary of latest scan stats."
    )
    last_modification_date: Optional[int] = Field(
        None, description="Timestamp when object was last modified (UTC)."
    )
    last_submission_date: Optional[int] = Field(
        None, description="Most recent submission timestamp (UTC)."
    )
    main_icon: Optional[Dict[str, str]] = Field(
        None, description="Main icon hashes: 'raw_md5' and 'dhash'."
    )
    md5: Optional[str] = Field(None, description="MD5 hash of the file.")
    meaningful_name: Optional[str] = Field(
        None, description="Most representative file name."
    )
    names: Optional[List[str]] = Field(None, description="All associated file names.")
    permhash: Optional[str] = Field(None, description="Permhash of the file.")
    reputation: Optional[int] = Field(None, description="Community reputation score.")
    sandbox_verdicts: Optional[Dict[str, SandboxVerdict]] = Field(
        None, description="Verdicts from various sandboxes."
    )
    sha1: Optional[str] = Field(None, description="SHA1 hash of the file.")
    sha256: Optional[str] = Field(None, description="SHA256 hash of the file.")
    sigma_analysis_results: Optional[List[SigmaAnalysisResult]] = Field(
        None, description="List of Sigma rule matches."
    )
    sigma_analysis_stats: Optional[SigmaAnalysisStats] = Field(
        None, description="Stats for Sigma analysis."
    )
    sigma_analysis_summary: Optional[Dict[str, SigmaAnalysisStats]] = Field(
        None, description="Sigma stats split by ruleset name."
    )
    size: Optional[int] = Field(None, description="File size in bytes.")
    tags: Optional[List[str]] = Field(
        None, description="Representative tags for the file."
    )
    tlsh: Optional[str] = Field(None, description="TLSH hash of the file.")
    times_submitted: Optional[int] = Field(
        None, description="Number of times submitted to Google TI."
    )
    total_votes: Optional[Dict[str, int]] = Field(
        None, description="Total community votes (harmless vs malicious)."
    )
    type_description: Optional[str] = Field(
        None, description="Description of the file type."
    )
    type_extension: Optional[str] = Field(None, description="File extension.")
    type_tag: Optional[str] = Field(None, description="Tag representing file type.")
    unique_sources: Optional[int] = Field(
        None, description="Number of unique submission sources."
    )
    vhash: Optional[str] = Field(None, description="VHash similarity clustering value.")
    crowdsourced_ids_results: Optional[List[CrowdsourcedIDsResult]] = Field(
        None, description="List of crowdsourced IDS results."
    )
    crowdsourced_ids_stats: Optional[CrowdsourcedIDsStats] = Field(
        None, description="Stats for crowdsourced IDS results."
    )
    crowdsourced_yara_results: Optional[List[CrowdsourcedYaraResult]] = Field(
        None, description="List of crowdsourced YARA matches."
    )


class GTIFileData(BaseModel):
    """Model representing the 'data' section for a file."""

    id: str = Field(..., description="SHA256 identifier of the file.")
    type: str = Field("file", description="Resource type, set to 'file'.")
    links: Optional[Dict[str, str]] = Field(
        None, description="Links related to the file resource."
    )
    attributes: Optional[FileModel] = Field(
        None, description="Attributes of the file resource."
    )


class GTIFileResponse(BaseModel):
    """Model representing a response containing file data."""

    data: GTIFileData
