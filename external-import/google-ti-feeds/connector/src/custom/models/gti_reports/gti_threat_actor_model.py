"""Model representing a Google Threat Intelligence Threat Actor."""

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class AggregationCommonalities(BaseModel):
    """Technical commonalities among all domains, files, IP addresses, and URLs tied to the threat actor."""

    domains: Optional[Dict[str, Any]] = Field(
        None,
        description="Technical commonalities among all domains tied to the threat actor.",
    )
    files: Optional[Dict[str, Any]] = Field(
        None,
        description="Technical commonalities among all files tied to the threat actor.",
    )
    ip_addresses: Optional[Dict[str, Any]] = Field(
        None,
        description="Technical commonalities among all IP addresses tied to the threat actor.",
    )
    urls: Optional[Dict[str, Any]] = Field(
        None,
        description="Technical commonalities among all URLs tied to the threat actor.",
    )


class Counters(BaseModel):
    """Count of technical commonalities among all domains, files, IP addresses, and URLs tied to the threat actor."""

    attack_techniques: int = Field(
        ...,
        description="Number of MITRE ATT&CK techniques associated with the threat actor.",
    )
    domains: int = Field(
        ..., description="Number of domains related to the threat actor."
    )
    files: int = Field(..., description="Number of files related to the threat actor.")
    iocs: int = Field(
        ...,
        description="Number of IoCs related to the threat actor (files + URLs + domains + IP addresses).",
    )
    ip_addresses: int = Field(
        ..., description="Number of IP addresses related to the threat actor."
    )
    subscribers: int = Field(
        ..., description="Number of users subscribed to the threat actor."
    )
    urls: int = Field(..., description="Number of URLs related to the threat actor.")


class AltNameDetail(BaseModel):
    """Alternative names/aliases by which the threat actor could be known."""

    confidence: str = Field(
        ...,
        description="Confidence on the information or the attribution of the alternative name.",
    )
    description: Optional[str] = Field(
        None, description="Additional information related to the alternative name."
    )
    first_seen: Optional[int] = Field(
        None,
        description="The first time the alternative name was attributed (UTC timestamp).",
    )
    last_seen: Optional[int] = Field(
        None,
        description="The last time the alternative name was attributed (UTC timestamp).",
    )
    value: str = Field(..., description="Alternative name/alias.")


class SeenDetail(BaseModel):
    """Details about when the threat actor was first or last seen."""

    confidence: str = Field(
        ..., description="Confidence on the information or the attribution."
    )
    description: Optional[str] = Field(
        None, description="Additional information about the activity."
    )
    first_seen: Optional[int] = Field(
        None, description="First time this date was attributed (UTC timestamp)."
    )
    last_seen: Optional[int] = Field(
        None, description="Last time this date was attributed (UTC timestamp)."
    )
    value: str = Field(
        ...,
        description="Date when the observation was made (YYYY-MM-DDTHH:mm:ssZ format).",
    )


class MergedActor(BaseModel):
    """Actors confirmed to be part of a larger group (current threat actor)."""

    confidence: str = Field(
        ...,
        description="Confidence on the information or the attribution of the merged threat actor.",
    )
    description: Optional[str] = Field(
        None, description="Additional information about the merged actor."
    )
    first_seen: Optional[int] = Field(
        None,
        description="First time this merged threat actor was attributed (UTC timestamp).",
    )
    last_seen: Optional[int] = Field(
        None,
        description="Last time this merged threat actor was attributed (UTC timestamp).",
    )
    value: str = Field(..., description="Name of the merged threat actor.")


class Motivation(BaseModel):
    """Threat actor's motivations such as espionage, financial gain, etc."""

    confidence: str = Field(
        ...,
        description="Confidence on the information or the attribution of the motivation.",
    )
    description: Optional[str] = Field(
        None, description="Additional information about the motivation."
    )
    first_seen: Optional[int] = Field(
        None,
        description="First time this motivation was attributed (UTC timestamp).",
    )
    last_seen: Optional[int] = Field(
        None,
        description="Last time this motivation was attributed (UTC timestamp).",
    )
    value: str = Field(..., description="Threat actor's motivation.")


class SourceRegion(BaseModel):
    """Country or region from which the threat actor is known to originate."""

    confidence: str = Field(
        ...,
        description="Confidence on the information related to the source region.",
    )
    country: Optional[str] = Field(None, description="Country of threat actor origin.")
    country_iso2: Optional[str] = Field(
        None, description="Source country in ISO 3166 Alpha2 code format."
    )
    description: Optional[str] = Field(
        None, description="Additional information about the source region."
    )
    first_seen: Optional[int] = Field(
        None,
        description="First time this source region was attributed (UTC timestamp).",
    )
    last_seen: Optional[int] = Field(
        None, description="Last time this source region was attributed (UTC timestamp)."
    )
    region: Optional[str] = Field(None, description="Region of threat actor origin.")
    source: Optional[str] = Field(None, description="Information's supplier.")
    sub_region: Optional[str] = Field(
        None, description="Subregion of threat actor origin."
    )


class TagDetail(BaseModel):
    """Tags associated with the threat actor with additional context."""

    confidence: str = Field(
        ..., description="Confidence on the tag association to the threat actor."
    )
    description: Optional[str] = Field(
        None, description="Additional information related to the tag."
    )
    first_seen: Optional[int] = Field(
        None, description="First time this tag was attributed (UTC timestamp)."
    )
    last_seen: Optional[int] = Field(
        None, description="Last time this tag was attributed (UTC timestamp)."
    )
    value: str = Field(..., description="Value of the tag.")


class TargetedIndustry(BaseModel):
    """Industries and industry groups known to be targeted by the threat actor."""

    confidence: str = Field(
        ..., description="Confidence on the industry targeted by the threat actor."
    )
    description: Optional[str] = Field(
        None, description="Additional information related to the targeted industry."
    )
    first_seen: Optional[int] = Field(
        None,
        description="First time this targeted industry was associated (UTC timestamp).",
    )
    industry: Optional[str] = Field(
        None, description="Sub-industry targeted by the threat actor."
    )
    industry_group: str = Field(
        ..., description="Industry group targeted by the threat actor."
    )
    last_seen: Optional[int] = Field(
        None,
        description="Last time this targeted industry was associated (UTC timestamp).",
    )
    source: Optional[str] = Field(None, description="Information's supplier.")


class TargetedRegion(BaseModel):
    """Regions and countries known to be targeted by the threat actor."""

    confidence: str = Field(
        ...,
        description="Confidence on the threat actor's targeted region association.",
    )
    country: Optional[str] = Field(
        None, description="Country targeted by the threat actor."
    )
    country_iso2: Optional[str] = Field(
        None, description="Targeted country in ISO 3166 Alpha2 code format."
    )
    description: Optional[str] = Field(
        None, description="Additional information related to the targeted region."
    )
    first_seen: Optional[int] = Field(
        None,
        description="First time this targeted region was associated (UTC timestamp).",
    )
    last_seen: Optional[int] = Field(
        None,
        description="Last time this targeted region was associated (UTC timestamp).",
    )
    region: Optional[str] = Field(
        None, description="Region targeted by the threat actor."
    )
    source: Optional[str] = Field(None, description="Information's supplier.")
    sub_region: Optional[str] = Field(
        None, description="Sub-region targeted by the threat actor."
    )


class ThreatActorModel(BaseModel):
    """Model representing a GTI threat actor."""

    name: str = Field(..., description="Threat actor's name.")
    collection_type: Optional[str] = Field(
        None,
        description="Type of object; typically 'threat_actor'.",
    )
    creation_date: int = Field(
        ..., description="UTC timestamp of threat actor object creation."
    )
    last_modification_date: int = Field(
        ..., description="UTC timestamp of last threat actor update."
    )
    description: Optional[str] = Field(
        None, description="Description/context about the threat actor."
    )
    status: Optional[str] = Field(
        None,
        description="Status of attribute computation: PENDING_RECOMPUTE or COMPUTED.",
    )
    private: bool = Field(
        ..., description="Whether the threat actor object is private."
    )
    origin: Optional[str] = Field(
        None,
        description="Source of the information: Partner or Google Threat Intelligence.",
    )

    recent_activity_relative_change: Optional[float] = Field(
        None, description="Ratio of recent activity change (14-day interval)."
    )
    recent_activity_summary: Optional[List[int]] = Field(
        None, description="Time series of IoC activity (14-day)."
    )
    top_icon_md5: Optional[List[str]] = Field(
        None, description="List of the 3 most frequent icons' MD5 hashes."
    )

    counters: Optional[Counters] = Field(
        None, description="Counters for related indicators and metadata."
    )
    aggregations: Optional[AggregationCommonalities] = Field(
        None, description="Grouped common traits across related IoCs."
    )
    alt_names_details: Optional[List[AltNameDetail]] = Field(
        None, description="Alternative names/aliases for the threat actor."
    )
    first_seen_details: Optional[List[SeenDetail]] = Field(
        None, description="Information about when the threat actor was first seen."
    )
    last_seen_details: Optional[List[SeenDetail]] = Field(
        None, description="Information about when the threat actor was last seen."
    )
    merged_actors: Optional[List[MergedActor]] = Field(
        None, description="Actors confirmed to be part of this threat actor group."
    )
    motivations: Optional[List[Motivation]] = Field(
        None,
        description="Threat actor's motivations such as espionage, financial gain, etc.",
    )
    source_regions_hierarchy: Optional[List[SourceRegion]] = Field(
        None, description="Regions/countries of threat actor origin."
    )
    tags_details: Optional[List[TagDetail]] = Field(
        None, description="Tags applied to the threat actor, with context."
    )
    targeted_industries_tree: Optional[List[TargetedIndustry]] = Field(
        None, description="Industries targeted by the threat actor."
    )
    targeted_regions_hierarchy: Optional[List[TargetedRegion]] = Field(
        None, description="Regions/countries targeted by the threat actor."
    )


class GTIThreatActorData(BaseModel):
    """Model representing data for a GTI threat actor."""

    id: str
    type: Optional[str] = None
    links: Optional[Dict[str, str]] = None
    attributes: Optional[ThreatActorModel] = None
    context_attributes: Optional[Dict[str, Any]] = None


class GTIThreatActorResponse(BaseModel):
    """Model representing a response containing GTI threat actor data."""

    data: Union[GTIThreatActorData, List[GTIThreatActorData]]
