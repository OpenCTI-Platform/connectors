"""Google Threat Intelligence Campaign Models."""

from typing import Any

from pydantic import BaseModel, Field


class AggregationValue(BaseModel):
    """Aggregation value model for technical commonalities."""

    confidence: str | None = Field(
        default=None, description="Confidence level of the aggregation"
    )
    description: str | None = Field(
        default=None, description="Description of the aggregation"
    )
    first_seen: int | None = Field(
        default=None, description="First time this aggregation was seen (UTC timestamp)"
    )
    last_seen: int | None = Field(
        default=None, description="Last time this aggregation was seen (UTC timestamp)"
    )
    source: str | None = Field(default=None, description="Information supplier")
    value: str | dict[str, Any] | None = Field(
        default=None, description="Aggregation value"
    )


class CrowdsourcedResult(BaseModel):
    """Crowdsourced result with dict-based value."""

    confidence: str | None = Field(
        default=None, description="Confidence level of the result"
    )
    description: str | None = Field(
        default=None, description="Description of the result"
    )
    first_seen: int | None = Field(
        default=None, description="First time this result was seen (UTC timestamp)"
    )
    last_seen: int | None = Field(
        default=None, description="Last time this result was seen (UTC timestamp)"
    )
    source: str | None = Field(default=None, description="Information supplier")
    value: dict[str, Any] | None = Field(
        default=None, description="Result details as dictionary"
    )


class FilesAggregation(BaseModel):
    """Files aggregation model with all possible fields."""

    model_config = {"extra": "allow"}

    # Specific crowdsourced result fields
    crowdsourced_ids_results: list[CrowdsourcedResult] | None = Field(
        default=None, description="Crowdsourced IDS results"
    )
    crowdsourced_yara_results: list[CrowdsourcedResult] | None = Field(
        default=None, description="Crowdsourced YARA results"
    )
    crowdsourced_sigma_results: list[CrowdsourcedResult] | None = Field(
        default=None, description="Crowdsourced Sigma results"
    )
    suggested_threat_label: str | list[str] | None = Field(
        default=None, description="Suggested threat labels"
    )


class Aggregations(BaseModel):
    """dictionary of commonalities between different IoCs associated with the campaign."""

    domains: dict[str, list[AggregationValue]] | None = Field(
        default=None,
        description="Technical commonalities among all domains tied to the campaign",
    )
    files: FilesAggregation | None = Field(
        default=None,
        description="Technical commonalities among all files tied to the campaign",
    )
    ip_addresses: dict[str, list[AggregationValue]] | None = Field(
        default=None,
        description="Technical commonalities among all IP addresses tied to the campaign",
    )
    urls: dict[str, list[AggregationValue]] | None = Field(
        default=None,
        description="Technical commonalities among all URLs tied to the campaign",
    )


class AltNameDetail(BaseModel):
    """Alternative name details for campaign."""

    confidence: str | None = Field(
        default=None,
        description="Confidence on the information or the attribution of the alternative name to the campaign",
    )
    description: str | None = Field(
        default=None,
        description="Additional information related to the alternative name",
    )
    first_seen: int | None = Field(
        default=None,
        description="First time that alternative name was attributed to the campaign (UTC timestamp)",
    )
    last_seen: int | None = Field(
        default=None,
        description="Last time that alternative name was attributed to the campaign (UTC timestamp)",
    )
    value: str | None = Field(default=None, description="Alternative name / alias")


class Counters(BaseModel):
    """dictionary of counters of related objects."""

    attack_techniques: int | None = Field(
        default=None,
        description="Number of MITRE ATT&CK techniques associated with the campaign",
    )
    domains: int | None = Field(
        default=None, description="Number of domains related to the campaign"
    )
    files: int | None = Field(
        default=None, description="Number of files related to the campaign"
    )
    iocs: int | None = Field(
        default=None,
        description="Number of IoCs (files + URLs + domains + IP addresses) related to the campaign",
    )
    ip_addresses: int | None = Field(
        default=None, description="Number of IP addresses related to the campaign"
    )
    subscribers: int | None = Field(
        default=None, description="Number of users subscribed to the campaign"
    )
    urls: int | None = Field(
        default=None, description="Number of URLs related to the campaign"
    )


class ActivityDetail(BaseModel):
    """Base model for activity details (first_seen and last_seen)."""

    confidence: str | None = Field(
        default=None,
        description="Confidence on the information or the attribution of the activity",
    )
    description: str | None = Field(
        default=None,
        description="Description / additional information about the activity",
    )
    first_seen: int | None = Field(
        default=None,
        description="First time this activity date has been attributed to the campaign (UTC timestamp)",
    )
    last_seen: int | None = Field(
        default=None,
        description="Last time this activity date has been attributed to the campaign (UTC timestamp)",
    )
    value: str | None = Field(
        default=None,
        description="Date when the observation about the campaign was made (YYYY-MM-DDTHH:mm:ssZ format)",
    )


class SourceRegion(BaseModel):
    """Country or region from which the campaign is known to originate."""

    confidence: str | None = Field(
        default=None,
        description="Confidence on the information or the source region of the malicious campaign",
    )
    country: str | None = Field(
        default=None,
        description="Country from which the malicious campaign is known to originate",
    )
    country_iso2: str | None = Field(
        default=None, description="Source country in ISO 3166 Alpha2 - code format"
    )
    description: str | None = Field(
        default=None,
        description="Description / additional information about the country or region",
    )
    first_seen: int | None = Field(
        default=None,
        description="First time this source region was attributed to the campaign (UTC timestamp)",
    )
    last_seen: int | None = Field(
        default=None,
        description="Last time this source region was attributed to the campaign (UTC timestamp)",
    )
    region: str | None = Field(
        default=None,
        description="Region from which the malicious campaign is known to originate",
    )
    source: str | None = Field(default=None, description="Information supplier")
    sub_region: str | None = Field(
        default=None,
        description="Subregion from which the malicious campaign is known to originate",
    )


class SummaryStatsEntry(BaseModel):
    """Summary statistics entry with min, max, and avg values."""

    min: float | None = Field(default=None, description="Minimum value")
    max: float | None = Field(default=None, description="Maximum value")
    avg: float | None = Field(default=None, description="Average value")


class SummaryStats(BaseModel):
    """Stats associated with the campaign."""

    first_submission_date: SummaryStatsEntry | None = Field(
        default=None,
        description="Min, max and avg values of first_submission_date of all IoCs associated to the campaign",
    )
    last_submission_date: SummaryStatsEntry | None = Field(
        default=None,
        description="Min, max and avg values of last_submission_date of all IoCs associated to the campaign",
    )
    files_detections: SummaryStatsEntry | None = Field(
        default=None,
        description="Min, max and avg values of files_detections of all IoCs associated to the campaign",
    )
    urls_detections: SummaryStatsEntry | None = Field(
        default=None,
        description="Min, max and avg values of urls_detections of all IoCs associated to the campaign",
    )


class TagDetail(BaseModel):
    """Tag details associated with the campaign."""

    confidence: str | None = Field(
        default=None,
        description="Confidence on the information or the tag association to the campaign",
    )
    description: str | None = Field(
        default=None,
        description="Description / additional information related to the tag associated to the campaign",
    )
    first_seen: int | None = Field(
        default=None,
        description="First time this tag was attributed to the campaign (UTC timestamp)",
    )
    last_seen: int | None = Field(
        default=None,
        description="Last time this tag was attributed to the campaign (UTC timestamp)",
    )
    value: str | None = Field(default=None, description="Value of the tag")


class TargetedIndustry(BaseModel):
    """Industries and industry groups known to be targeted by the campaign."""

    confidence: str | None = Field(
        default=None,
        description="Confidence on the information or the industry targeted by the campaign",
    )
    description: str | None = Field(
        default=None,
        description="Description / additional information related to the industry targeted by the campaign",
    )
    first_seen: int | None = Field(
        default=None,
        description="First time this targeted industry was associated with the campaign (UTC timestamp)",
    )
    industry: str | None = Field(
        default=None, description="Sub-industry targeted by the campaign"
    )
    industry_group: str = Field(
        ..., description="Industry group targeted by the campaign"
    )
    last_seen: int | None = Field(
        default=None,
        description="Last time this targeted industry was associated with the campaign (UTC timestamp)",
    )
    source: str | None = Field(default=None, description="Information supplier")


class TargetedRegion(BaseModel):
    """Regions and countries known to be targeted by the campaign."""

    confidence: str | None = Field(
        default=None,
        description="Confidence on the information related to the region targeted by the malicious campaign",
    )
    country: str | None = Field(
        default=None, description="Country targeted by the malicious campaign"
    )
    country_iso2: str | None = Field(
        default=None, description="Targeted country in ISO 3166 Alpha2 - code format"
    )
    description: str | None = Field(
        default=None,
        description="Description / additional information about the region targeted by the malicious campaign",
    )
    first_seen: int | None = Field(
        default=None,
        description="First time this targeted region was associated with the campaign (UTC timestamp)",
    )
    last_seen: int | None = Field(
        default=None,
        description="Last time this targeted region was associated with the campaign (UTC timestamp)",
    )
    region: str | None = Field(
        default=None, description="Region targeted by the malicious campaign"
    )
    sub_region: str | None = Field(
        default=None, description="Sub-region targeted by the malicious campaign"
    )
    source: str | None = Field(default=None, description="Information supplier")


class CampaignModel(BaseModel):
    """Google Threat Intelligence Campaign model."""

    aggregations: Aggregations | None = Field(
        default=None,
        description="dictionary of commonalities between different IoCs associated with the campaign",
    )
    alt_names_details: list[AltNameDetail] | None = Field(
        default=None,
        description="Alternative names / aliases by which the campaign could be known",
    )
    collection_type: str | None = Field(
        default=None,
        description="Type of the object. For campaigns the value is 'campaign'",
    )
    counters: Counters | None = Field(
        default=None, description="dictionary of counters of related objects"
    )
    creation_date: int = Field(
        ..., description="Campaign object creation date (UTC timestamp)"
    )
    description: str | None = Field(
        default=None, description="Description / context about the campaign"
    )
    first_seen_details: list[ActivityDetail] | None = Field(
        default=None,
        description="Additional information related to the campaign's first activity",
    )
    last_modification_date: int = Field(
        ...,
        description="Last time when the campaign's information was updated (UTC timestamp)",
    )
    last_seen_details: list[ActivityDetail] | None = Field(
        default=None,
        description="Additional information related to the campaign's last activity",
    )
    name: str = Field(..., description="Campaign's name")
    origin: str | None = Field(
        default=None,
        description="Source of the information. Google Threat Intelligence for curated objects",
    )
    private: bool | None = Field(
        default=None, description="Whether the campaign object is private or not"
    )
    recent_activity_relative_change: float | None = Field(
        default=None,
        description="Ratio of change between the last two recent activity periods (14 days)",
    )
    recent_activity_summary: list[int] | None = Field(
        default=None,
        description="Time series representing the activity of IoCs related to the campaign (2 weeks)",
    )
    status: str | None = Field(
        default=None,
        description="Indicates if the object has attributes pending to be computed again. Values: PENDING_RECOMPUTE, COMPUTED",
    )
    source_regions_hierarchy: list[SourceRegion] | None = Field(
        default=None,
        description="Country or region from which the campaign is known to originate",
    )
    summary_stats: SummaryStats | None = Field(
        default=None, description="Stats associated with the campaign"
    )
    tags: list[str] | None = Field(
        default=None, description="Tags associated with the campaign"
    )
    tags_details: list[TagDetail] | None = Field(
        default=None,
        description="Tags associated with the campaign with additional context",
    )
    targeted_industries_tree: list[TargetedIndustry] | None = Field(
        default=None,
        description="Industries and industry groups known to be targeted by the campaign",
    )
    targeted_regions_hierarchy: list[TargetedRegion] | None = Field(
        default=None,
        description="Regions and countries known to be targeted by the campaign",
    )
    top_icon_md5: list[str] | None = Field(
        default=None,
        description="list of the 3 most frequent icons among the campaign's associated IoCs (MD5 hash)",
    )


class Links(BaseModel):
    """Links related to the campaign."""

    self: str | None = Field(default=None, description="Self link")


class GTICampaignMeta(BaseModel):
    """GTI Campaign metadata."""

    count: int | None = Field(default=None, description="Count of campaigns")
    cursor: str | None = Field(default=None, description="Cursor for pagination.")


class GTICampaignData(BaseModel):
    """GTI Campaign data container."""

    attributes: CampaignModel | None = Field(
        default=None, description="Campaign attributes"
    )
    id: str | None = Field(default=None, description="Campaign ID")
    links: Links | None = Field(default=None, description="Campaign links")
    type: str | None = Field(default=None, description="Campaign type")


class GTICampaignResponse(BaseModel):
    """GTI Campaign API response model."""

    data: list[GTICampaignData] | None = Field(
        default=None, description="list of campaign data"
    )
    links: Links | None = Field(default=None, description="Response links")
    meta: GTICampaignMeta | None = Field(default=None, description="Response metadata")

    def validate_data_structure(self) -> bool:
        """Validate the basic structure of the GTI campaign response."""
        if not self.data:
            return False

        for campaign_data in self.data:
            if not campaign_data.attributes:
                return False

        return True
