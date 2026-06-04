"""Model representing a Google Threat Intelligence Software Toolkit."""

from typing import Any

from pydantic import BaseModel, Field


class AggregationCommonalities(BaseModel):
    """Commonalities between IoCs associated with the software or toolkit, grouped by type."""

    domains: dict[str, Any] | None = Field(
        None,
        description="Technical commonalities among all domains tied to the software or toolkit.",
    )
    files: dict[str, Any] | None = Field(
        None,
        description="Technical commonalities among all files tied to the software or toolkit.",
    )
    ip_addresses: dict[str, Any] | None = Field(
        None,
        description="Technical commonalities among all IP addresses tied to the software or toolkit.",
    )
    urls: dict[str, Any] | None = Field(
        None,
        description="Technical commonalities among all URLs tied to the software or toolkit.",
    )


class AltNameDetail(BaseModel):
    """Alternative names/aliases by which the software toolkit could be known."""

    confidence: str | None = Field(
        default=None,
        description="Confidence on the information or the attribution of the alternative name.",
    )
    description: str | None = Field(
        default=None,
        description="Additional information related to the alternative name.",
    )
    first_seen: int | None = Field(
        default=None,
        description="The first time the alternative name was attributed (UTC timestamp).",
    )
    last_seen: int | None = Field(
        default=None,
        description="The last time the alternative name was attributed (UTC timestamp).",
    )
    value: str = Field(..., description="Alternative name/alias.")


class Capability(BaseModel):
    """Capability associated with the software or toolkit."""

    confidence: str | None = Field(
        None,
        description="The confidence of the software or toolkit's associated capability.",
    )
    description: str | None = Field(None, description="Description of the capability.")
    first_seen: int | None = Field(
        None,
        description="First time the capability was associated with the software or toolkit (UTC timestamp).",
    )
    last_seen: int | None = Field(
        None,
        description="Last time the capability was associated with the software or toolkit (UTC timestamp).",
    )
    value: str = Field(..., description="Capability name.")


class Counters(BaseModel):
    """Count of related objects for the software or toolkit."""

    attack_techniques: int | None = Field(
        None,
        description="Number of MITRE ATT&CK techniques associated with the software or toolkit.",
    )
    domains: int | None = Field(
        None, description="Number of domains related to the software or toolkit."
    )
    files: int | None = Field(
        None, description="Number of files related to the software or toolkit."
    )
    iocs: int | None = Field(
        None,
        description="Number of IoCs (files + URLs + domains + IP addresses) related to the software or toolkit.",
    )
    ip_addresses: int | None = Field(
        None,
        description="Number of IP addresses related to the software or toolkit.",
    )
    subscribers: int | None = Field(
        None,
        description="Number of users subscribed to the software or toolkit.",
    )
    urls: int | None = Field(
        None, description="Number of URLs related to the software or toolkit."
    )


class DetectionName(BaseModel):
    """External detection name associated with the software or toolkit."""

    confidence: str | None = Field(
        None,
        description="The confidence of the detection name associated to the software or toolkit.",
    )
    description: str | None = Field(
        None, description="Descriptive information related to the detection name."
    )
    first_seen: int | None = Field(
        None,
        description="First time the detection name was associated (UTC timestamp).",
    )
    last_seen: int | None = Field(
        None,
        description="Last time the detection name was associated (UTC timestamp).",
    )
    value: str = Field(..., description="The detection name.")


class SeenDetail(BaseModel):
    """Details about when the software or toolkit was first or last seen."""

    confidence: str | None = Field(
        None, description="Confidence on the information or the attribution."
    )
    description: str | None = Field(
        None, description="Additional information about the activity."
    )
    first_seen: int | None = Field(
        None, description="First time this date was attributed (UTC timestamp)."
    )
    last_seen: int | None = Field(
        None, description="Last time this date was attributed (UTC timestamp)."
    )
    value: str | None = Field(
        None,
        description="Date when the observation was made (YYYY-MM-DDTHH:mm:ssZ format).",
    )


class MalwareRole(BaseModel):
    """Malware role associated with the software or toolkit."""

    value: str = Field(..., description="The malware role name.")
    first_seen: int | None = Field(
        None,
        description="First time the malware role was associated (UTC timestamp).",
    )
    last_seen: int | None = Field(
        None,
        description="Last time the malware role was associated (UTC timestamp).",
    )
    confidence: str | None = Field(
        None, description="Confidence of the associated malware role."
    )
    description: str | None = Field(
        None, description="Descriptive information related to the malware role."
    )


class Motivation(BaseModel):
    """Motivation of the threat actor using the software or toolkit."""

    confidence: str | None = Field(
        None, description="Confidence on the associated motivation."
    )
    description: str | None = Field(
        None, description="Additional information about the motivation."
    )
    first_seen: int | None = Field(
        None,
        description="First time this motivation was associated (UTC timestamp).",
    )
    last_seen: int | None = Field(
        None,
        description="Last time this motivation was associated (UTC timestamp).",
    )
    value: str = Field(..., description="Motivation name.")


class OperatingSystem(BaseModel):
    """Operating system affected by the software or toolkit."""

    value: str = Field(..., description="Affected operating system.")
    first_seen: int | None = Field(
        None,
        description="First time the OS was associated with the software or toolkit (UTC timestamp).",
    )
    last_seen: int | None = Field(
        None,
        description="Last time the OS was associated with the software or toolkit (UTC timestamp).",
    )
    confidence: str | None = Field(
        None,
        description="Confidence that the operating system is affected by the software or toolkit.",
    )
    description: str | None = Field(
        None,
        description="Descriptive information related to the targeted operating system.",
    )


class SourceRegion(BaseModel):
    """Region/country from which the software or toolkit is known to originate."""

    confidence: str | None = Field(None, description="Confidence on the source region.")
    country: str | None = Field(None, description="Country of origin.")
    country_iso2: str | None = Field(
        None, description="Source country in ISO 3166 Alpha2 format."
    )
    description: str | None = Field(
        None, description="Additional information about the source region."
    )
    first_seen: int | None = Field(
        None,
        description="First time this source region was attributed (UTC timestamp).",
    )
    last_seen: int | None = Field(
        None,
        description="Last time this source region was attributed (UTC timestamp).",
    )
    region: str | None = Field(None, description="Region of origin.")
    source: str | None = Field(None, description="Information's supplier.")
    sub_region: str | None = Field(None, description="Sub-region of origin.")


class SummaryStats(BaseModel):
    """Stats associated with the software and toolkit's IoCs."""

    first_submission_date: dict[str, Any] | None = Field(
        None,
        description="Min, max and average values of first_submission_date across associated IoCs.",
    )
    last_submission_date: dict[str, Any] | None = Field(
        None,
        description="Min, max and average values of last_submission_date across associated IoCs.",
    )
    files_detections: dict[str, Any] | None = Field(
        None,
        description="Min, max and average values of files_detections across associated IoCs.",
    )
    urls_detections: dict[str, Any] | None = Field(
        None,
        description="Min, max and average values of urls_detections across associated IoCs.",
    )


class TargetedIndustry(BaseModel):
    """Industry known to be targeted by the software or toolkit."""

    confidence: str | None = Field(
        None, description="Confidence on the targeted industry."
    )
    description: str | None = Field(
        None, description="Additional information about the targeted industry."
    )
    first_seen: int | None = Field(
        None,
        description="First time this targeted industry was associated (UTC timestamp).",
    )
    industry: str | None = Field(
        None, description="Sub-industry targeted by the software or toolkit."
    )
    industry_group: str | None = Field(
        None, description="Industry group targeted by the software or toolkit."
    )
    last_seen: int | None = Field(
        None,
        description="Last time this targeted industry was associated (UTC timestamp).",
    )
    source: str | None = Field(None, description="Information's supplier.")


class TargetedRegion(BaseModel):
    """Region/country known to be targeted by the software or toolkit."""

    confidence: str | None = Field(
        None, description="Confidence on the targeted region."
    )
    country: str | None = Field(None, description="Targeted country.")
    country_iso2: str | None = Field(
        None, description="Targeted country in ISO 3166 Alpha2 format."
    )
    description: str | None = Field(
        None, description="Additional information about the targeted region."
    )
    first_seen: int | None = Field(
        None,
        description="First time this targeted region was associated (UTC timestamp).",
    )
    last_seen: int | None = Field(
        None,
        description="Last time this targeted region was associated (UTC timestamp).",
    )
    region: str | None = Field(
        None, description="Software or toolkit's targeted region."
    )
    source: str | None = Field(None, description="Information's supplier.")
    sub_region: str | None = Field(
        None, description="Software or toolkit's targeted sub-region."
    )


class SoftwareToolkitModel(BaseModel):
    """Model representing a GTI software toolkit."""

    name: str = Field(..., description="Software or toolkit's name.")
    collection_type: str | None = Field(
        default=None,
        description="Type of object; for software and toolkits the value is 'software_toolkits'.",
    )
    creation_date: int = Field(
        ..., description="Software or toolkit object creation date (UTC timestamp)."
    )
    last_modification_date: int = Field(
        ...,
        description="Last time when the software or toolkit's information was updated (UTC timestamp).",
    )
    description: str | None = Field(
        default=None,
        description="Description/context about the software or toolkit.",
    )
    private: bool | None = Field(
        default=None,
        description="Whether the software or toolkit object is private.",
    )
    origin: str | None = Field(
        default=None,
        description="Source of the information: Partner or Google Threat Intelligence.",
    )
    link: str | None = Field(default=None, description="URL to extra resources.")
    status: str | None = Field(
        default=None,
        description="Status of attribute computation: PENDING_RECOMPUTE or COMPUTED.",
    )
    tlp: str | None = Field(
        default=None,
        description="TLP level indicating data sensitivity: RED, AMBER, GREEN, or CLEAR.",
    )
    sponsor_region: str | None = Field(
        default=None,
        description="Main country or region suspected to sponsor the threat that uses the software or toolkit.",
    )
    source_region: str | None = Field(
        default=None,
        description="Main country or region from which the threat is known to originate.",
    )
    recent_activity_relative_change: float | None = Field(
        default=None,
        description="Ratio of change between the last two 'recent activity' periods (14-day interval).",
    )

    # Simple list fields
    alt_names: list[str] | None = Field(
        default=None,
        description="List of alternative names/aliases by which the software or toolkit is known.",
    )
    tags: list[str] | None = Field(
        default=None,
        description="Tags associated with the software and toolkit.",
    )
    targeted_industries: list[str] | None = Field(
        default=None,
        description="List of industries known to be targeted by the software or toolkit.",
    )
    targeted_regions: list[str] | None = Field(
        default=None,
        description="List of regions and countries known to be targeted by the software or toolkit.",
    )
    top_icon_md5: list[str] | None = Field(
        default=None,
        description="List of the 3 most frequent icons' MD5 hashes among associated IoCs.",
    )
    recent_activity_summary: list[int] | None = Field(
        default=None,
        description="Time series of IoC activity related to the software or toolkit (2 weeks).",
    )

    # Complex list fields
    alt_names_details: list[AltNameDetail] | None = Field(
        default=None,
        description="Alternative names/aliases with attribution confidence and dates.",
    )
    capabilities: list[Capability] | None = Field(
        default=None,
        description="Capabilities associated with the software or toolkit.",
    )
    detection_names: list[DetectionName] | None = Field(
        default=None,
        description="External detection names associated with the software or toolkit.",
    )
    first_seen_details: list[SeenDetail] | None = Field(
        default=None,
        description="Additional information about the software or toolkit's first activity.",
    )
    last_seen_details: list[SeenDetail] | None = Field(
        default=None,
        description="Additional information about the software or toolkit's last activity.",
    )
    malware_roles: list[MalwareRole] | None = Field(
        default=None,
        description="Malware roles associated with the software or toolkit.",
    )
    motivations: list[Motivation] | None = Field(
        default=None,
        description="Motivations of the threat actor using the software or toolkit.",
    )
    operating_systems: list[OperatingSystem] | None = Field(
        default=None,
        description="Operating systems affected by the software or toolkit.",
    )
    source_regions_hierarchy: list[SourceRegion] | None = Field(
        default=None,
        description="Countries/regions from which the software or toolkit is known to originate.",
    )
    targeted_industries_tree: list[TargetedIndustry] | None = Field(
        default=None,
        description="Industries and industry groups known to be targeted.",
    )
    targeted_regions_hierarchy: list[TargetedRegion] | None = Field(
        default=None,
        description="Regions and countries known to be targeted.",
    )

    # Complex dict/object fields
    aggregations: AggregationCommonalities | None = Field(
        default=None,
        description="Commonalities between IoCs associated with the software or toolkit, grouped by IoC type.",
    )
    counters: Counters | None = Field(
        default=None,
        description="Counters of related objects (IoCs, techniques, subscribers, etc.).",
    )
    summary_stats: list[SummaryStats] | SummaryStats | None = Field(
        default=None,
        description="Stats associated with the software and toolkit's IoCs.",
    )


class Links(BaseModel):
    """Model representing links to related resources."""

    self: str
    next: str | None = Field(None, description="Link to the next page of results.")


class GTISoftwareToolkitMeta(BaseModel):
    """Model representing metadata for a GTI software toolkit."""

    count: int
    cursor: str | None = Field(None, description="Cursor for pagination.")


class GTISoftwareToolkitData(BaseModel):
    """Model representing data for a GTI software toolkit."""

    id: str
    type: str | None = None
    links: Links | None = None
    attributes: SoftwareToolkitModel | None = None
    context_attributes: dict[str, Any] | None = None


class GTISoftwareToolkitResponse(BaseModel):
    """Model representing a response containing GTI software toolkit data."""

    data: GTISoftwareToolkitData | list[GTISoftwareToolkitData]

    meta: GTISoftwareToolkitMeta | None = Field(
        default=None,
        description="Metadata for the response. May be absent when no data is returned.",
    )
    links: Links
