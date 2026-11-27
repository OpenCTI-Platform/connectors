"""Module containing models for GTI domain response from Google Threat Intelligence API."""

from typing import Any

from connector.src.custom.models.gti.gti_assessment_model import (
    GTIAssessment,
    LastAnalysisStats,
)
from pydantic import BaseModel, Field


class Favicon(BaseModel):
    """Model representing a domain's favicon hashes."""

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
    engine_version: str | None = Field(
        None, description="Version of the scanning engine."
    )
    method: str | None = Field(
        None,
        description="Type of service provided by the URL scanner (e.g., 'blacklist').",
    )
    result: str | None = Field(
        None, description="Raw result from the URL scanner (e.g., 'clean', 'phishing')."
    )


class LastDnsRecord(BaseModel):
    """Model representing a single DNS record."""

    expire: int | None = Field(None, description="Expire field of the DNS record.")
    flag: int | None = Field(None, description="Flag field of the DNS record.")
    minimum: int | None = Field(None, description="Minimum TTL of the DNS record.")
    priority: int | None = Field(None, description="Priority of the DNS record.")
    refresh: int | None = Field(None, description="Refresh field of the DNS record.")
    rname: str | None = Field(None, description="Responsible party for the DNS record.")
    retry: int | None = Field(None, description="Retry field of the DNS record.")
    serial: int | None = Field(None, description="Serial number of the DNS record.")
    tag: str | None = Field(None, description="Tag of the DNS record.")
    ttl: int | None = Field(None, description="Time-to-live of the DNS record.")
    type: str | None = Field(
        None, description="Type of the DNS record (e.g., 'A', 'MX')."
    )
    value: str | None = Field(None, description="Value of the DNS record.")


class PopularityRank(BaseModel):
    """Model representing a domain's rank in a popularity service."""

    rank: int | None = Field(None, description="Rank position.")
    timestamp: int | None = Field(
        None, description="Timestamp when the rank was recorded (UTC). "
    )


class TotalVotes(BaseModel):
    """Model representing total community votes."""

    harmless: int | None = Field(None, description="Number of votes marking harmless.")
    malicious: int | None = Field(
        None, description="Number of votes marking malicious."
    )


class DomainModel(BaseModel):
    """Model representing attributes of a domain object."""

    categories: dict[str, str] | None = Field(
        None, description="Mapping of categorization services to assigned category."
    )
    creation_date: int | None = Field(
        None, description="Creation date from WHOIS (UTC timestamp)."
    )
    favicon: Favicon | None = Field(
        None, description="Favicon hash information (premium only)."
    )
    gti_assessment: GTIAssessment | None = Field(
        None, description="Google Threat Intelligence assessment for the domain."
    )
    jarm: str | None = Field(None, description="JARM hash of the domain.")
    last_analysis_date: int | None = Field(
        None, description="Timestamp of last domain scan (UTC)."
    )
    last_analysis_results: dict[str, LastAnalysisResult] | None = Field(
        None, description="Results from individual URL scanners."
    )
    last_analysis_stats: LastAnalysisStats | None = Field(
        None, description="Aggregated analysis statistics."
    )
    last_dns_records: list[LastDnsRecord] | None = Field(
        None, description="list of DNS records from last scan."
    )
    last_dns_records_date: int | None = Field(
        None, description="Timestamp when DNS records were retrieved (UTC)."
    )
    last_https_certificate: dict[str, Any] | None = Field(
        None, description="SSL Certificate object from last analysis."
    )
    last_https_certificate_date: int | None = Field(
        None, description="Timestamp when the HTTPS certificate was retrieved (UTC)."
    )
    last_modification_date: int | None = Field(
        None, description="Timestamp when domain information was last modified (UTC)."
    )
    last_update_date: int | None = Field(
        None, description="Timestamp from WHOIS last update (UTC)."
    )
    popularity_ranks: dict[str, PopularityRank] | None = Field(
        None, description="Domain's rank positions in popularity services."
    )
    registrar: str | None = Field(None, description="Registrar company of the domain.")
    reputation: int | None = Field(
        None, description="Community-calculated reputation score."
    )
    tags: list[str] | None = Field(
        None, description="list of representative tags for the domain."
    )
    total_votes: TotalVotes | None = Field(
        None, description="Community vote breakdown for the domain."
    )
    whois: str | None = Field(
        None, description="WHOIS information as returned by the WHOIS server."
    )
    whois_date: int | None = Field(
        None, description="Timestamp of last WHOIS record update (UTC)."
    )


class GTIDomainData(BaseModel):
    """Model representing the 'data' section for a domain."""

    id: str = Field(..., description="Domain name or identifier.")
    type: str = Field("domain", description="Resource type, set to 'domain'.")
    links: dict[str, str] | None = Field(
        None, description="Links related to the domain resource."
    )
    attributes: DomainModel | None = Field(
        None, description="Attributes of the domain resource."
    )


class GTIDomainResponse(BaseModel):
    """Model representing a response containing domain data."""

    data: GTIDomainData
