"""Module containing models for GTI reports response from Google Threat Intelligence API."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AggregationCommonalities(BaseModel):
    """Technical commonalities among all domains, files, IP addresses, and URLs tied to the report."""

    domains: Optional[Dict[str, Any]] = Field(
        None,
        description="Technical commonalities among all domains tied to the report.",
    )
    files: Optional[Dict[str, Any]] = Field(
        None, description="Technical commonalities among all files tied to the report."
    )
    ip_addresses: Optional[Dict[str, Any]] = Field(
        None,
        description="Technical commonalities among all IP addresses tied to the report.",
    )
    urls: Optional[Dict[str, Any]] = Field(
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
    description: Optional[str] = Field(
        None, description="Additional information about the threat's motivation."
    )
    first_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the motivation was first seen."
    )
    last_seen: Optional[int] = Field(
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
    country: Optional[str] = Field(None, description="Country of threat origin.")
    country_iso2: Optional[str] = Field(
        None, description="ISO 3166 Alpha2 country code."
    )
    description: Optional[str] = Field(
        None, description="Additional context about the source region."
    )
    first_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the source region was first seen."
    )
    last_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the source region was last seen."
    )
    region: Optional[str] = Field(None, description="Region of threat origin.")
    source: Optional[str] = Field(
        None, description="Supplier of this source region information."
    )
    sub_region: Optional[str] = Field(None, description="Sub-region of threat origin.")


class TagDetail(BaseModel):
    """Tags associated with the report with some additional context."""

    confidence: str = Field(
        ..., description="Confidence in the tag's association with the report."
    )
    description: Optional[str] = Field(
        None, description="Additional context about the tag."
    )
    first_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the tag was first seen."
    )
    last_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the tag was last seen."
    )
    value: str = Field(..., description="Tag value.")


class TargetedIndustry(BaseModel):
    """Industries and industry groups known to be targeted by the threat described in the report."""

    confidence: str = Field(
        ..., description="Confidence in the attribution of the targeted industry."
    )
    description: Optional[str] = Field(
        None, description="Additional info about the targeted industry."
    )
    first_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the industry was first targeted."
    )
    last_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the industry was last seen targeted."
    )
    industry: Optional[str] = Field(
        ..., description="Sub-industry targeted by the threat."
    )
    industry_group: str = Field(
        ..., description="Industry group targeted by the threat."
    )
    source: Optional[str] = Field(
        None, description="Supplier of this industry targeting information."
    )


class TargetedRegion(BaseModel):
    """Regions and countries known to be targeted by the threat described in the report."""

    confidence: str = Field(
        ..., description="Confidence in the attribution of the targeted region."
    )
    country: Optional[str] = Field(None, description="Country targeted by the threat.")
    country_iso2: Optional[str] = Field(
        None, description="ISO 3166 Alpha2 code for the country."
    )
    description: Optional[str] = Field(
        None, description="Additional context on the targeted region."
    )
    first_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the region was first targeted."
    )
    last_seen: Optional[int] = Field(
        ..., description="UTC timestamp when the region was last seen targeted."
    )
    region: Optional[str] = Field(None, description="Region targeted by the threat.")
    source: Optional[str] = Field(
        None, description="Supplier of this region targeting information."
    )
    sub_region: Optional[str] = Field(
        None, description="Sub-region targeted by the threat."
    )


class Technology(BaseModel):
    """Common Platform Enumeration (CPE) objects referring to the vulnerability described by the report."""

    cpe: Optional[str] = Field(None, description="CPE standardized product identifier.")
    cpe_title: Optional[str] = Field(
        None, description="Human-readable vendor and technology name."
    )
    technology_name: Optional[str] = Field(
        None, description="Technology affected by the vulnerability."
    )
    vendor: Optional[str] = Field(
        None, description="Vendor affected by the vulnerability."
    )


class ReportModel(BaseModel):
    """Model representing a GTI report."""

    report_id: Optional[str] = Field(None, description="Identifier of the report.")
    name: str = Field(..., description="Title of the report.")
    author: Optional[str] = Field(None, description="Author of the report.")
    collection_type: str = Field(
        ..., description="Type of object; always 'report' here."
    )
    creation_date: int = Field(..., description="UTC timestamp of report creation.")
    last_modification_date: int = Field(
        ..., description="UTC timestamp of last report update."
    )
    content: Optional[str] = Field(None, description="Full report content.")
    executive_summary: Optional[str] = Field(
        None, description="Summary of the report's content."
    )
    autogenerated_summary: Optional[str] = Field(
        None, description="ML-generated summary of the report."
    )
    analyst_comment: Optional[str] = Field(
        None, description="Comments made by GTI analysts."
    )
    report_type: Optional[str] = Field(
        None, description="Type of report: News, Actor Profile, OSINT, etc."
    )
    report_confidence: Optional[str] = Field(
        None, description="Confidence in the report's content/source."
    )
    status: Optional[str] = Field(
        None,
        description="Status of attribute computation: PENDING_RECOMPUTE or COMPUTED.",
    )
    link: Optional[str] = Field(None, description="URL to the original report.")

    version: Optional[int] = Field(None, description="Version number of the report.")
    private: bool = Field(..., description="Whether the report is private.")
    origin: Optional[str] = Field(
        None,
        description="Source of the information: Partner, Google TI, or Crowdsourced.",
    )

    affected_systems: Optional[List[str]] = Field(
        None, description="Systems affected by the threat."
    )
    intended_effects: Optional[List[str]] = Field(
        None, description="Intended effects of the threat."
    )
    targeted_informations: Optional[List[str]] = Field(
        None, description="Types of info targeted by the threat."
    )
    threat_categories: Optional[List[str]] = Field(
        None, description="Threat categories based on IoCs."
    )
    threat_scape: Optional[List[str]] = Field(
        None, description="Topic areas covered by the report."
    )
    top_icon_md5: Optional[List[str]] = Field(
        None, description="MD5 hashes of the most frequent favicons/icons."
    )
    recent_activity_relative_change: Optional[float] = Field(
        None, description="Ratio of recent activity change (14-day interval)."
    )
    recent_activity_summary: Optional[List[int]] = Field(
        None, description="Time series of IoC activity (14-day)."
    )

    counters: Optional[Counters] = Field(
        None, description="Counters for related indicators and metadata."
    )
    aggregations: Optional[AggregationCommonalities] = Field(
        None, description="Grouped common traits across related IoCs."
    )
    motivations: Optional[List[Motivation]] = Field(
        None, description="Motivations behind the threat actor’s behavior."
    )
    source_regions_hierarchy: Optional[List[SourceRegion]] = Field(
        None, description="Regions/countries of threat origin."
    )
    tags_details: Optional[List[TagDetail]] = Field(
        None, description="Tags applied to the report, with context."
    )
    targeted_industries_tree: Optional[List[TargetedIndustry]] = Field(
        None, description="Industries targeted by the threat."
    )
    targeted_regions_hierarchy: Optional[List[TargetedRegion]] = Field(
        None, description="Regions/countries targeted by the threat."
    )
    technologies: Optional[List[Technology]] = Field(
        None, description="Technologies and vendors affected by vulnerabilities."
    )


class Links(BaseModel):
    """Model representing links to related resources."""

    self: str
    next: Optional[str] = Field(None, description="Link to the next page of results.")


class GTIReportMeta(BaseModel):
    """Model representing metadata for a GTI report."""

    count: int
    cursor: Optional[str] = Field(None, description="Cursor for pagination.")


class GTIReportData(BaseModel):
    """Model representing data for a GTI report."""

    id: str
    type: str
    links: Links
    attributes: Optional[ReportModel]
    context_attributes: Dict[str, Any]


class GTIReportResponse(BaseModel):
    """Model representing a response containing GTI report data."""

    data: List[GTIReportData] = []
    meta: Optional[GTIReportMeta] = Field(
        default=None,
        description="Metadata for the response. May be absent when no data is returned.",
    )
    links: Links
