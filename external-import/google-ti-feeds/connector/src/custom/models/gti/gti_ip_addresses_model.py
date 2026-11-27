"""Module containing models for GTI IPaddresses response from Google Threat Intelligence API."""

from connector.src.custom.models.gti.gti_assessment_model import (
    GTIAssessment,
    LastAnalysisStats,
)
from pydantic import BaseModel, Field


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
