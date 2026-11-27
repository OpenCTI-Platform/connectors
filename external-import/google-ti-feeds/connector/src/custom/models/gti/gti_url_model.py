"""Module containing models for GTI URL response from Google Threat Intelligence API."""

from typing import Any

from connector.src.custom.models.gti.gti_assessment_model import (
    GTIAssessment,
    LastAnalysisStats,
)
from pydantic import BaseModel, Field


class Favicon(BaseModel):
    """Model representing a URL's favicon hashes."""

    dhash: str | None = Field(None, description="Difference hash of the favicon.")
    raw_md5: str | None = Field(None, description="MD5 hash of the favicon.")


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
