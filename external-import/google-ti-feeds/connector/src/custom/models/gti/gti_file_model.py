"""Module containing models for GTI File response from Google Threat Intelligence API."""

from connector.src.custom.models.gti.gti_assessment_model import (
    GTIAssessment,
    LastAnalysisStats,
)
from pydantic import BaseModel, ConfigDict, Field


class CrowdsourcedAlertContext(BaseModel):
    """Context for a single IDS alert."""

    dest_ip: str | None = Field(None, description="Destination IP of the alert.")
    dest_port: int | None = Field(None, description="Destination port of the alert.")
    hostname: str | None = Field(None, description="Hostname involved in the alert.")
    protocol: str | None = Field(None, description="Protocol used in the alert.")
    src_ip: str | None = Field(None, description="Source IP of the alert.")
    src_port: int | None = Field(None, description="Source port of the alert.")
    url: str | None = Field(None, description="URL involved in the alert.")


class CrowdsourcedIDsResult(BaseModel):
    """Model representing a crowdsourced IDS detection."""

    alert_context: list[CrowdsourcedAlertContext] | None = Field(
        None, description="list of contexts where the IDS triggered."
    )
    alert_severity: str | None = Field(None, description="Severity of the IDS alert.")
    rule_category: str | None = Field(None, description="Category of the IDS rule.")
    rule_id: str | None = Field(None, description="Identifier for the IDS rule.")
    rule_msg: str | None = Field(None, description="Message for the IDS rule.")
    rule_source: str | None = Field(None, description="Source of the IDS rule.")


class CrowdsourcedIDsStats(BaseModel):
    """Statistics for crowdsourced IDS results."""

    info: int | None = Field(None, description="Count of info-level alerts.")
    high: int | None = Field(None, description="Count of high-severity alerts.")
    low: int | None = Field(None, description="Count of low-severity alerts.")
    medium: int | None = Field(None, description="Count of medium-severity alerts.")


class CrowdsourcedYaraResult(BaseModel):
    """Model representing a crowdsourced YARA match."""

    description: str | None = Field(None, description="Description of the YARA match.")
    match_in_subfile: bool | None = Field(
        None, description="Whether match was in a subfile."
    )
    rule_name: str | None = Field(None, description="Name of the YARA rule.")
    ruleset_id: str | None = Field(None, description="Identifier for the YARA ruleset.")
    ruleset_name: str | None = Field(None, description="Name of the YARA ruleset.")
    source: str | None = Field(None, description="Source of the YARA rule.")


class LastAnalysisResult(BaseModel):
    """Result from a single antivirus engine."""

    # The GTI API sometimes returns `engine_update` as a Unix timestamp (int)
    # instead of a string; coerce so one engine entry cannot fail the whole file.
    model_config = ConfigDict(coerce_numbers_to_str=True)

    category: str | None = Field(None, description="Normalized result category.")
    engine_name: str | None = Field(None, description="Name of the antivirus engine.")
    engine_update: str | None = Field(None, description="Date of the engine update.")
    engine_version: str | None = Field(None, description="Version of the engine.")
    method: str | None = Field(
        None, description="Detection method (e.g., 'blacklist')."
    )
    result: str | None = Field(
        None, description="Raw scan result (e.g., 'clean', 'malicious')."
    )


class SandboxVerdict(BaseModel):
    """Summary of sandbox verdict for a specific sandbox."""

    category: str | None = Field(None, description="Normalized verdict category.")
    confidence: int | None = Field(None, description="Verdict confidence (0-100).")
    malware_classification: list[str] | None = Field(
        None, description="Raw sandbox classifications."
    )
    malware_names: list[str] | None = Field(
        None, description="Detected malware family names."
    )
    sandbox_name: str | None = Field(None, description="Name of the sandbox.")


class SigmaAnalysisResultContext(BaseModel):
    """Context for a matched Sigma rule."""

    values: dict[str, str] | None = Field(
        None, description="Matched key-value context."
    )


class SigmaAnalysisResult(BaseModel):
    """Detail for a single Sigma analysis rule match."""

    rule_title: str | None = Field(None, description="Title of the Sigma rule.")
    rule_source: str | None = Field(None, description="Source of the Sigma rule.")
    match_context: list[SigmaAnalysisResultContext] | None = Field(
        None, description="Context values for the match."
    )
    rule_level: str | None = Field(
        None, description="Severity level of the Sigma rule."
    )
    rule_description: str | None = Field(
        None, description="Description of the Sigma rule."
    )
    rule_author: str | None = Field(None, description="Author of the Sigma rule.")
    rule_id: str | None = Field(None, description="Identifier of the Sigma rule.")


class SigmaAnalysisStats(BaseModel):
    """Summary stats for Sigma analysis."""

    critical: int | None = Field(None, description="Count of critical matches.")
    high: int | None = Field(None, description="Count of high-severity matches.")
    low: int | None = Field(None, description="Count of low-severity matches.")
    medium: int | None = Field(None, description="Count of medium-severity matches.")


class ThreatSeverityData(BaseModel):
    """Data the GTI threat severity of a file was computed from."""

    popular_threat_category: str | None = Field(
        None, description="Most common threat category, e.g. 'trojan'."
    )
    type_tag: str | None = Field(None, description="File type tag.")
    has_similar_files_with_detections: bool | None = Field(
        None, description="Whether similar files are detected."
    )


class ThreatSeverity(BaseModel):
    """GTI threat severity of a file."""

    threat_severity_level: str | None = Field(
        None, description="Severity level, e.g. 'SEVERITY_HIGH'."
    )
    level_description: str | None = Field(
        None, description="Explanation of the severity level."
    )
    last_analysis_date: int | None = Field(
        None, description="Date of the severity computation (UTC timestamp)."
    )
    threat_severity_data: ThreatSeverityData | None = Field(
        None, description="Data the severity was computed from."
    )


class FileModel(BaseModel):
    """Model representing attributes of a file object."""

    capabilities_tags: list[str] | None = Field(
        None, description="list of capability tags (premium only)."
    )
    creation_date: int | None = Field(
        None, description="File build/compile timestamp (UTC)."
    )
    downloadable: bool | None = Field(
        None, description="Whether the file is downloadable (premium only)."
    )
    first_submission_date: int | None = Field(
        None, description="First submission timestamp (UTC)."
    )
    gti_assessment: GTIAssessment | None = Field(
        None, description="GTI assessment for the file."
    )
    last_analysis_date: int | None = Field(
        None, description="Most recent scan timestamp (UTC)."
    )
    last_analysis_results: dict[str, LastAnalysisResult] | None = Field(
        None, description="Latest scan results by engine."
    )
    last_analysis_stats: LastAnalysisStats | None = Field(
        None, description="Summary of latest scan stats."
    )
    last_modification_date: int | None = Field(
        None, description="Timestamp when object was last modified (UTC)."
    )
    last_submission_date: int | None = Field(
        None, description="Most recent submission timestamp (UTC)."
    )
    main_icon: dict[str, str] | None = Field(
        None, description="Main icon hashes: 'raw_md5' and 'dhash'."
    )
    md5: str | None = Field(None, description="MD5 hash of the file.")
    meaningful_name: str | None = Field(
        None, description="Most representative file name."
    )
    names: list[str] | None = Field(None, description="All associated file names.")
    permhash: str | None = Field(None, description="Permhash of the file.")
    reputation: int | None = Field(None, description="Community reputation score.")
    sandbox_verdicts: dict[str, SandboxVerdict] | None = Field(
        None, description="Verdicts from various sandboxes."
    )
    sha1: str | None = Field(None, description="SHA1 hash of the file.")
    sha256: str | None = Field(None, description="SHA256 hash of the file.")
    sigma_analysis_results: list[SigmaAnalysisResult] | None = Field(
        None, description="list of Sigma rule matches."
    )
    sigma_analysis_stats: SigmaAnalysisStats | None = Field(
        None, description="Stats for Sigma analysis."
    )
    sigma_analysis_summary: dict[str, SigmaAnalysisStats] | None = Field(
        None, description="Sigma stats split by ruleset name."
    )
    size: int | None = Field(None, description="File size in bytes.")
    tags: list[str] | None = Field(
        None, description="Representative tags for the file."
    )
    threat_severity: ThreatSeverity | None = Field(
        None, description="GTI threat severity of the file."
    )
    tlsh: str | None = Field(None, description="TLSH hash of the file.")
    times_submitted: int | None = Field(
        None, description="Number of times submitted to Google TI."
    )
    total_votes: dict[str, int | None] | None = Field(
        None, description="Total community votes (harmless vs malicious)."
    )
    type_description: str | None = Field(
        None, description="Description of the file type."
    )
    type_extension: str | None = Field(None, description="File extension.")
    type_tag: str | None = Field(None, description="Tag representing file type.")
    unique_sources: int | None = Field(
        None, description="Number of unique submission sources."
    )
    vhash: str | None = Field(None, description="VHash similarity clustering value.")
    crowdsourced_ids_results: list[CrowdsourcedIDsResult] | None = Field(
        None, description="list of crowdsourced IDS results."
    )
    crowdsourced_ids_stats: CrowdsourcedIDsStats | None = Field(
        None, description="Stats for crowdsourced IDS results."
    )
    crowdsourced_yara_results: list[CrowdsourcedYaraResult] | None = Field(
        None, description="list of crowdsourced YARA matches."
    )


class GTIFileData(BaseModel):
    """Model representing the 'data' section for a file."""

    id: str = Field(..., description="SHA256 identifier of the file.")
    type: str = Field("file", description="Resource type, set to 'file'.")
    links: dict[str, str] | None = Field(
        None, description="Links related to the file resource."
    )
    attributes: FileModel | None = Field(
        None, description="Attributes of the file resource."
    )


class GTIFileResponse(BaseModel):
    """Model representing a response containing file data."""

    data: GTIFileData
