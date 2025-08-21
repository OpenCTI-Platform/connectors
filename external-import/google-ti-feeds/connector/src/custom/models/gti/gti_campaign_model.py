"""Google Threat Intelligence Campaign Models."""

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class AggregationValue(BaseModel):
    """Aggregation value model for technical commonalities."""

    confidence: Optional[str] = Field(
        default=None, description="Confidence level of the aggregation"
    )
    description: Optional[str] = Field(
        default=None, description="Description of the aggregation"
    )
    first_seen: Optional[int] = Field(
        default=None, description="First time this aggregation was seen (UTC timestamp)"
    )
    last_seen: Optional[int] = Field(
        default=None, description="Last time this aggregation was seen (UTC timestamp)"
    )
    source: Optional[str] = Field(default=None, description="Information supplier")
    value: Optional[Union[str, Dict[str, Any]]] = Field(
        default=None, description="Aggregation value"
    )


class CrowdsourcedResult(BaseModel):
    """Crowdsourced result with dict-based value."""

    confidence: Optional[str] = Field(
        default=None, description="Confidence level of the result"
    )
    description: Optional[str] = Field(
        default=None, description="Description of the result"
    )
    first_seen: Optional[int] = Field(
        default=None, description="First time this result was seen (UTC timestamp)"
    )
    last_seen: Optional[int] = Field(
        default=None, description="Last time this result was seen (UTC timestamp)"
    )
    source: Optional[str] = Field(default=None, description="Information supplier")
    value: Optional[Dict[str, Any]] = Field(
        default=None, description="Result details as dictionary"
    )


class FilesAggregation(BaseModel):
    """Files aggregation model with all possible fields."""

    model_config = {"extra": "allow"}

    # Specific crowdsourced result fields
    crowdsourced_ids_results: Optional[List[CrowdsourcedResult]] = Field(
        default=None, description="Crowdsourced IDS results"
    )
    crowdsourced_yara_results: Optional[List[CrowdsourcedResult]] = Field(
        default=None, description="Crowdsourced YARA results"
    )
    crowdsourced_sigma_results: Optional[List[CrowdsourcedResult]] = Field(
        default=None, description="Crowdsourced Sigma results"
    )
    suggested_threat_label: Optional[Union[str, List[str]]] = Field(
        default=None, description="Suggested threat labels"
    )


class Aggregations(BaseModel):
    """Dictionary of commonalities between different IoCs associated with the campaign."""

    domains: Optional[Dict[str, List[AggregationValue]]] = Field(
        default=None,
        description="Technical commonalities among all domains tied to the campaign",
    )
    files: Optional[FilesAggregation] = Field(
        default=None,
        description="Technical commonalities among all files tied to the campaign",
    )
    ip_addresses: Optional[Dict[str, List[AggregationValue]]] = Field(
        default=None,
        description="Technical commonalities among all IP addresses tied to the campaign",
    )
    urls: Optional[Dict[str, List[AggregationValue]]] = Field(
        default=None,
        description="Technical commonalities among all URLs tied to the campaign",
    )


class AltNameDetail(BaseModel):
    """Alternative name details for campaign."""

    confidence: Optional[str] = Field(
        default=None,
        description="Confidence on the information or the attribution of the alternative name to the campaign",
    )
    description: Optional[str] = Field(
        default=None,
        description="Additional information related to the alternative name",
    )
    first_seen: Optional[int] = Field(
        default=None,
        description="First time that alternative name was attributed to the campaign (UTC timestamp)",
    )
    last_seen: Optional[int] = Field(
        default=None,
        description="Last time that alternative name was attributed to the campaign (UTC timestamp)",
    )
    value: Optional[str] = Field(default=None, description="Alternative name / alias")


class Counters(BaseModel):
    """Dictionary of counters of related objects."""

    attack_techniques: Optional[int] = Field(
        default=None,
        description="Number of MITRE ATT&CK techniques associated with the campaign",
    )
    domains: Optional[int] = Field(
        default=None, description="Number of domains related to the campaign"
    )
    files: Optional[int] = Field(
        default=None, description="Number of files related to the campaign"
    )
    iocs: Optional[int] = Field(
        default=None,
        description="Number of IoCs (files + URLs + domains + IP addresses) related to the campaign",
    )
    ip_addresses: Optional[int] = Field(
        default=None, description="Number of IP addresses related to the campaign"
    )
    subscribers: Optional[int] = Field(
        default=None, description="Number of users subscribed to the campaign"
    )
    urls: Optional[int] = Field(
        default=None, description="Number of URLs related to the campaign"
    )


class ActivityDetail(BaseModel):
    """Base model for activity details (first_seen and last_seen)."""

    confidence: Optional[str] = Field(
        default=None,
        description="Confidence on the information or the attribution of the activity",
    )
    description: Optional[str] = Field(
        default=None,
        description="Description / additional information about the activity",
    )
    first_seen: Optional[int] = Field(
        default=None,
        description="First time this activity date has been attributed to the campaign (UTC timestamp)",
    )
    last_seen: Optional[int] = Field(
        default=None,
        description="Last time this activity date has been attributed to the campaign (UTC timestamp)",
    )
    value: Optional[str] = Field(
        default=None,
        description="Date when the observation about the campaign was made (YYYY-MM-DDTHH:mm:ssZ format)",
    )


class SourceRegion(BaseModel):
    """Country or region from which the campaign is known to originate."""

    confidence: Optional[str] = Field(
        default=None,
        description="Confidence on the information or the source region of the malicious campaign",
    )
    country: Optional[str] = Field(
        default=None,
        description="Country from which the malicious campaign is known to originate",
    )
    country_iso2: Optional[str] = Field(
        default=None, description="Source country in ISO 3166 Alpha2 - code format"
    )
    description: Optional[str] = Field(
        default=None,
        description="Description / additional information about the country or region",
    )
    first_seen: Optional[int] = Field(
        default=None,
        description="First time this source region was attributed to the campaign (UTC timestamp)",
    )
    last_seen: Optional[int] = Field(
        default=None,
        description="Last time this source region was attributed to the campaign (UTC timestamp)",
    )
    region: Optional[str] = Field(
        default=None,
        description="Region from which the malicious campaign is known to originate",
    )
    source: Optional[str] = Field(default=None, description="Information supplier")
    sub_region: Optional[str] = Field(
        default=None,
        description="Subregion from which the malicious campaign is known to originate",
    )


class SummaryStatsEntry(BaseModel):
    """Summary statistics entry with min, max, and avg values."""

    min: Optional[float] = Field(default=None, description="Minimum value")
    max: Optional[float] = Field(default=None, description="Maximum value")
    avg: Optional[float] = Field(default=None, description="Average value")


class SummaryStats(BaseModel):
    """Stats associated with the campaign."""

    first_submission_date: Optional[SummaryStatsEntry] = Field(
        default=None,
        description="Min, max and avg values of first_submission_date of all IoCs associated to the campaign",
    )
    last_submission_date: Optional[SummaryStatsEntry] = Field(
        default=None,
        description="Min, max and avg values of last_submission_date of all IoCs associated to the campaign",
    )
    files_detections: Optional[SummaryStatsEntry] = Field(
        default=None,
        description="Min, max and avg values of files_detections of all IoCs associated to the campaign",
    )
    urls_detections: Optional[SummaryStatsEntry] = Field(
        default=None,
        description="Min, max and avg values of urls_detections of all IoCs associated to the campaign",
    )


class TagDetail(BaseModel):
    """Tag details associated with the campaign."""

    confidence: Optional[str] = Field(
        default=None,
        description="Confidence on the information or the tag association to the campaign",
    )
    description: Optional[str] = Field(
        default=None,
        description="Description / additional information related to the tag associated to the campaign",
    )
    first_seen: Optional[int] = Field(
        default=None,
        description="First time this tag was attributed to the campaign (UTC timestamp)",
    )
    last_seen: Optional[int] = Field(
        default=None,
        description="Last time this tag was attributed to the campaign (UTC timestamp)",
    )
    value: Optional[str] = Field(default=None, description="Value of the tag")


class TargetedIndustry(BaseModel):
    """Industries and industry groups known to be targeted by the campaign."""

    confidence: Optional[str] = Field(
        default=None,
        description="Confidence on the information or the industry targeted by the campaign",
    )
    description: Optional[str] = Field(
        default=None,
        description="Description / additional information related to the industry targeted by the campaign",
    )
    first_seen: Optional[int] = Field(
        default=None,
        description="First time this targeted industry was associated with the campaign (UTC timestamp)",
    )
    industry: Optional[str] = Field(
        default=None, description="Sub-industry targeted by the campaign"
    )
    industry_group: str = Field(
        ..., description="Industry group targeted by the campaign"
    )
    last_seen: Optional[int] = Field(
        default=None,
        description="Last time this targeted industry was associated with the campaign (UTC timestamp)",
    )
    source: Optional[str] = Field(default=None, description="Information supplier")


class TargetedRegion(BaseModel):
    """Regions and countries known to be targeted by the campaign."""

    confidence: Optional[str] = Field(
        default=None,
        description="Confidence on the information related to the region targeted by the malicious campaign",
    )
    country: Optional[str] = Field(
        default=None, description="Country targeted by the malicious campaign"
    )
    country_iso2: Optional[str] = Field(
        default=None, description="Targeted country in ISO 3166 Alpha2 - code format"
    )
    description: Optional[str] = Field(
        default=None,
        description="Description / additional information about the region targeted by the malicious campaign",
    )
    first_seen: Optional[int] = Field(
        default=None,
        description="First time this targeted region was associated with the campaign (UTC timestamp)",
    )
    last_seen: Optional[int] = Field(
        default=None,
        description="Last time this targeted region was associated with the campaign (UTC timestamp)",
    )
    region: Optional[str] = Field(
        default=None, description="Region targeted by the malicious campaign"
    )
    sub_region: Optional[str] = Field(
        default=None, description="Sub-region targeted by the malicious campaign"
    )
    source: Optional[str] = Field(default=None, description="Information supplier")


class CampaignModel(BaseModel):
    """Google Threat Intelligence Campaign model."""

    aggregations: Optional[Aggregations] = Field(
        default=None,
        description="Dictionary of commonalities between different IoCs associated with the campaign",
    )
    alt_names_details: Optional[List[AltNameDetail]] = Field(
        default=None,
        description="Alternative names / aliases by which the campaign could be known",
    )
    collection_type: Optional[str] = Field(
        default=None,
        description="Type of the object. For campaigns the value is 'campaign'",
    )
    counters: Optional[Counters] = Field(
        default=None, description="Dictionary of counters of related objects"
    )
    creation_date: int = Field(
        ..., description="Campaign object creation date (UTC timestamp)"
    )
    description: Optional[str] = Field(
        default=None, description="Description / context about the campaign"
    )
    first_seen_details: Optional[List[ActivityDetail]] = Field(
        default=None,
        description="Additional information related to the campaign's first activity",
    )
    last_modification_date: int = Field(
        ...,
        description="Last time when the campaign's information was updated (UTC timestamp)",
    )
    last_seen_details: Optional[List[ActivityDetail]] = Field(
        default=None,
        description="Additional information related to the campaign's last activity",
    )
    name: str = Field(..., description="Campaign's name")
    origin: Optional[str] = Field(
        default=None,
        description="Source of the information. Google Threat Intelligence for curated objects",
    )
    private: Optional[bool] = Field(
        default=None, description="Whether the campaign object is private or not"
    )
    recent_activity_relative_change: Optional[float] = Field(
        default=None,
        description="Ratio of change between the last two recent activity periods (14 days)",
    )
    recent_activity_summary: Optional[List[int]] = Field(
        default=None,
        description="Time series representing the activity of IoCs related to the campaign (2 weeks)",
    )
    status: Optional[str] = Field(
        default=None,
        description="Indicates if the object has attributes pending to be computed again. Values: PENDING_RECOMPUTE, COMPUTED",
    )
    source_regions_hierarchy: Optional[List[SourceRegion]] = Field(
        default=None,
        description="Country or region from which the campaign is known to originate",
    )
    summary_stats: Optional[SummaryStats] = Field(
        default=None, description="Stats associated with the campaign"
    )
    tags: Optional[List[str]] = Field(
        default=None, description="Tags associated with the campaign"
    )
    tags_details: Optional[List[TagDetail]] = Field(
        default=None,
        description="Tags associated with the campaign with additional context",
    )
    targeted_industries_tree: Optional[List[TargetedIndustry]] = Field(
        default=None,
        description="Industries and industry groups known to be targeted by the campaign",
    )
    targeted_regions_hierarchy: Optional[List[TargetedRegion]] = Field(
        default=None,
        description="Regions and countries known to be targeted by the campaign",
    )
    top_icon_md5: Optional[List[str]] = Field(
        default=None,
        description="List of the 3 most frequent icons among the campaign's associated IoCs (MD5 hash)",
    )


class Links(BaseModel):
    """Links related to the campaign."""

    self: Optional[str] = Field(default=None, description="Self link")


class GTICampaignMeta(BaseModel):
    """GTI Campaign metadata."""

    count: Optional[int] = Field(default=None, description="Count of campaigns")


class GTICampaignData(BaseModel):
    """GTI Campaign data container."""

    attributes: Optional[CampaignModel] = Field(
        default=None, description="Campaign attributes"
    )
    id: Optional[str] = Field(default=None, description="Campaign ID")
    links: Optional[Links] = Field(default=None, description="Campaign links")
    type: Optional[str] = Field(default=None, description="Campaign type")


class GTICampaignResponse(BaseModel):
    """GTI Campaign API response model."""

    data: Optional[List[GTICampaignData]] = Field(
        default=None, description="List of campaign data"
    )
    links: Optional[Links] = Field(default=None, description="Response links")
    meta: Optional[GTICampaignMeta] = Field(
        default=None, description="Response metadata"
    )

    def validate_data_structure(self) -> bool:
        """Validate the basic structure of the GTI campaign response."""
        if not self.data:
            return False

        for campaign_data in self.data:
            if not campaign_data.attributes:
                return False

        return True
