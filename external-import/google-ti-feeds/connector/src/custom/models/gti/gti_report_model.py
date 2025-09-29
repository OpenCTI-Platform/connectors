"""Module containing models for GTI reports response from Google Threat Intelligence API."""

from typing import Any

from pydantic import BaseModel, Field


class AggregationCommonalities(BaseModel):
    """Technical commonalities among all domains, files, IP addresses, and URLs tied to the report."""

    domains: dict[str, Any] | None = Field(
        None,
        description="Technical commonalities among all domains tied to the report.",
    )
    files: dict[str, Any] | None = Field(
        None, description="Technical commonalities among all files tied to the report."
    )
    ip_addresses: dict[str, Any] | None = Field(
        None,
        description="Technical commonalities among all IP addresses tied to the report.",
    )
    urls: dict[str, Any] | None = Field(
        None, description="Technical commonalities among all URLs tied to the report."
    )


class Counters(BaseModel):
    """Count of technical commonalities among all domains, files, IP addresses, and URLs tied to the report."""

    domains: int = Field(..., description="Number of domains related to the report.")
    files: int = Field(..., description="Number of files related to the report.")
    iocs: int = Field(
        ...,
        description="Number of IoCs related to the report (files + URLs + domains + IP addresses).",
    )
    ip_addresses: int = Field(
        ..., description="Number of IP addresses related to the report."
    )
    subscribers: int = Field(
        ..., description="Number of users subscribed to the report."
    )
    urls: int = Field(..., description="Number of URLs related to the report.")


class Motivation(BaseModel):
    """Motivations of the threat described in the report such as espionage, financial gain, etc."""

    confidence: str = Field(
        ...,
        description="Confidence level on the motivation's attribution to the threat.",
    )
    description: str | None = Field(
        None, description="Additional information about the threat's motivation."
    )
    first_seen: int | None = Field(
        ..., description="UTC timestamp when the motivation was first seen."
    )
    last_seen: int | None = Field(
        ..., description="UTC timestamp when the motivation was last seen."
    )
    value: str = Field(
        ..., description="Motivation of the threat (e.g. espionage, financial gain)."
    )


class SourceRegion(BaseModel):
    """Country or region from which the threat described in the report is known to originate."""

    confidence: str = Field(
        ...,
        description="Confidence level in the attribution of this region as a threat source.",
    )
    country: str | None = Field(None, description="Country of threat origin.")
    country_iso2: str | None = Field(None, description="ISO 3166 Alpha2 country code.")
    description: str | None = Field(
        None, description="Additional context about the source region."
    )
    first_seen: int | None = Field(
        ..., description="UTC timestamp when the source region was first seen."
    )
    last_seen: int | None = Field(
        ..., description="UTC timestamp when the source region was last seen."
    )
    region: str | None = Field(None, description="Region of threat origin.")
    source: str | None = Field(
        None, description="Supplier of this source region information."
    )
    sub_region: str | None = Field(None, description="Sub-region of threat origin.")


class TagDetail(BaseModel):
    """Tags associated with the report with some additional context."""

    confidence: str = Field(
        ..., description="Confidence in the tag's association with the report."
    )
    description: str | None = Field(
        None, description="Additional context about the tag."
    )
    first_seen: int | None = Field(
        ..., description="UTC timestamp when the tag was first seen."
    )
    last_seen: int | None = Field(
        ..., description="UTC timestamp when the tag was last seen."
    )
    value: str = Field(..., description="Tag value.")


class TargetedIndustry(BaseModel):
    """Industries and industry groups known to be targeted by the threat described in the report."""

    confidence: str = Field(
        ..., description="Confidence in the attribution of the targeted industry."
    )
    description: str | None = Field(
        None, description="Additional info about the targeted industry."
    )
    first_seen: int | None = Field(
        ..., description="UTC timestamp when the industry was first targeted."
    )
    last_seen: int | None = Field(
        ..., description="UTC timestamp when the industry was last seen targeted."
    )
    industry: str | None = Field(
        ..., description="Sub-industry targeted by the threat."
    )
    industry_group: str = Field(
        ..., description="Industry group targeted by the threat."
    )
    source: str | None = Field(
        None, description="Supplier of this industry targeting information."
    )


class TargetedRegion(BaseModel):
    """Regions and countries known to be targeted by the threat described in the report."""

    confidence: str = Field(
        ..., description="Confidence in the attribution of the targeted region."
    )
    country: str | None = Field(None, description="Country targeted by the threat.")
    country_iso2: str | None = Field(
        None, description="ISO 3166 Alpha2 code for the country."
    )
    description: str | None = Field(
        None, description="Additional context on the targeted region."
    )
    first_seen: int | None = Field(
        ..., description="UTC timestamp when the region was first targeted."
    )
    last_seen: int | None = Field(
        ..., description="UTC timestamp when the region was last seen targeted."
    )
    region: str | None = Field(None, description="Region targeted by the threat.")
    source: str | None = Field(
        None, description="Supplier of this region targeting information."
    )
    sub_region: str | None = Field(
        None, description="Sub-region targeted by the threat."
    )


class Technology(BaseModel):
    """Common Platform Enumeration (CPE) objects referring to the vulnerability described by the report."""

    cpe: str | None = Field(None, description="CPE standardized product identifier.")
    cpe_title: str | None = Field(
        None, description="Human-readable vendor and technology name."
    )
    technology_name: str | None = Field(
        None, description="Technology affected by the vulnerability."
    )
    vendor: str | None = Field(
        None, description="Vendor affected by the vulnerability."
    )


class ReportModel(BaseModel):
    """Model representing a GTI report."""

    report_id: str | None = Field(None, description="Identifier of the report.")
    name: str = Field(..., description="Title of the report.")
    author: str | None = Field(None, description="Author of the report.")
    collection_type: str = Field(
        ..., description="Type of object; always 'report' here."
    )
    creation_date: int = Field(..., description="UTC timestamp of report creation.")
    last_modification_date: int = Field(
        ..., description="UTC timestamp of last report update."
    )
    content: str | None = Field(None, description="Full report content.")
    executive_summary: str | None = Field(
        None, description="Summary of the report's content."
    )
    autogenerated_summary: str | None = Field(
        None, description="ML-generated summary of the report."
    )
    analyst_comment: str | None = Field(
        None, description="Comments made by GTI analysts."
    )
    report_type: str | None = Field(
        None, description="Type of report: News, Actor Profile, OSINT, etc."
    )
    report_confidence: str | None = Field(
        None, description="Confidence in the report's content/source."
    )
    status: str | None = Field(
        None,
        description="Status of attribute computation: PENDING_RECOMPUTE or COMPUTED.",
    )
    link: str | None = Field(None, description="URL to the original report.")

    version: int | None = Field(None, description="Version number of the report.")
    private: bool = Field(..., description="Whether the report is private.")
    origin: str | None = Field(
        None,
        description="Source of the information: Partner, Google TI, or Crowdsourced.",
    )

    affected_systems: list[str] | None = Field(
        None, description="Systems affected by the threat."
    )
    intended_effects: list[str] | None = Field(
        None, description="Intended effects of the threat."
    )
    targeted_informations: list[str] | None = Field(
        None, description="Types of info targeted by the threat."
    )
    threat_categories: list[str] | None = Field(
        None, description="Threat categories based on IoCs."
    )
    threat_scape: list[str] | None = Field(
        None, description="Topic areas covered by the report."
    )
    top_icon_md5: list[str] | None = Field(
        None, description="MD5 hashes of the most frequent favicons/icons."
    )
    recent_activity_relative_change: float | None = Field(
        None, description="Ratio of recent activity change (14-day interval)."
    )
    recent_activity_summary: list[int] | None = Field(
        None, description="Time series of IoC activity (14-day)."
    )

    counters: Counters | None = Field(
        None, description="Counters for related indicators and metadata."
    )
    aggregations: AggregationCommonalities | None = Field(
        None, description="Grouped common traits across related IoCs."
    )
    motivations: list[Motivation] | None = Field(
        None, description="Motivations behind the threat actor's behavior."
    )
    source_regions_hierarchy: list[SourceRegion] | None = Field(
        None, description="Regions/countries of threat origin."
    )
    tags_details: list[TagDetail] | None = Field(
        None, description="Tags applied to the report, with context."
    )
    targeted_industries_tree: list[TargetedIndustry] | None = Field(
        None, description="Industries targeted by the threat."
    )
    targeted_regions_hierarchy: list[TargetedRegion] | None = Field(
        None, description="Regions/countries targeted by the threat."
    )
    technologies: list[Technology] | None = Field(
        None, description="Technologies and vendors affected by vulnerabilities."
    )


class Links(BaseModel):
    """Model representing links to related resources."""

    self: str
    next: str | None = Field(None, description="Link to the next page of results.")


class GTIReportMeta(BaseModel):
    """Model representing metadata for a GTI report."""

    count: int
    cursor: str | None = Field(None, description="Cursor for pagination.")


class GTIReportData(BaseModel):
    """Model representing data for a GTI report."""

    id: str
    type: str
    links: Links
    attributes: ReportModel | None
    context_attributes: dict[str, Any]


class GTIReportResponse(BaseModel):
    """Model representing a response containing GTI report data."""

    data: list[GTIReportData] = []
    meta: GTIReportMeta | None = Field(
        default=None,
        description="Metadata for the response. May be absent when no data is returned.",
    )
    links: Links
