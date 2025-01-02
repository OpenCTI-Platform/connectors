"""Offer python client and response models for the TAP Campaign API."""

from datetime import datetime, timedelta
from typing import Any, Literal, Optional, Sequence
from urllib.parse import urljoin

import aiohttp
from pydantic import AwareDatetime, Field

from proofpoint_tap.client_api.common import BaseTAPClient
from proofpoint_tap.errors import ProofpointAPIError
from proofpoint_tap.warnings import (
    BaseModelWithRecommendedFieldAndExtraWarning,
    RecommendedField,
)


# Models for /v2/campaign/ids response
class Campaign(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model /v2/campaign/ids response.

    Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API [consulted on December 12, 2024]
    """

    id: str = Field(..., description="Campaign ID")
    last_updated_at: AwareDatetime = Field(
        ..., description="Last updated timestamp of the campaign", alias="lastUpdatedAt"
    )


class CampaignIdsResponse(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model /v2/campaign/ids response.

    Reference:
        https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API [consulted on December 12, 2024]
    """

    campaigns: list[Campaign] = Field(..., description="List of campaigns")


# Models for /v2/campaign/<campaignId> response
class Actor(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model Actor from /v2/campaign/<campaignId> response."""

    name: str = Field(..., description="Name of the actor")
    id: str = Field(..., description="Actor identifier")


class Malware(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model Malware from /v2/campaign/<campaignId> response."""

    name: str = Field(..., description="Name of the malware family")
    id: str = Field(..., description="Malware family identifier")


class Technique(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model Technique from /v2/campaign/<campaignId> response."""

    name: str = Field(..., description="Name of the technique")
    id: str = Field(..., description="Technique identifier")


class Family(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model Family. Rather defined in /v2/threat/summary/<threatId> documentation."""

    id: str = Field(..., description="The unique identifier of the threat family")
    name: str = Field(..., description="The name of the threat family")


class Brand(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model Brand. Rather defined in /v2/threat/summary/<threatId> documentation."""

    id: str = Field(
        ..., description="The unique identifier of the brand associated with the threat"
    )
    name: str = Field(
        ..., description="The name of the brand associated with the threat"
    )


class CampaignMember(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model CampaignMember from /v2/campaign/<campaignId> response."""

    id: str = Field(..., description="Threat identifier")
    threat: str = Field(
        ..., description="Attachment hash or URL fragment of the threat"
    )
    type: Optional[str] = RecommendedField(
        None, description="The type of threat (attachment, url, or message text)"
    )
    sub_type: Optional[str] = Field(
        None,
        description="Sub-type of the threat: ATTACHMENT, COMPLETE_URL, etc.",
        alias="subType",
    )
    threat_time: AwareDatetime = Field(
        ...,
        description="Datetime the threat variant was first recognized as malicious",
        alias="threatTime",
    )
    threat_status: Literal["active", "cleared", "falsePositive"] = RecommendedField(
        None, description="Status of the threat.", alias="threatStatus"
    )


class CampaignDetailsResponse(BaseModelWithRecommendedFieldAndExtraWarning):
    """Model /v2/campaign/<campaignId> response.

    Reference: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API [consulted on December 12, 2024]
    """

    id: str = Field(..., description="Campaign ID")
    name: str = Field(..., description="Name of the campaign")
    description: str = Field(..., description="Description of the campaign")
    start_date: AwareDatetime = Field(
        ...,
        description="Start date of the campaign in ISO8601 format",
        alias="startDate",
    )
    campaign_members: Sequence[CampaignMember] = Field(
        ..., description="List of campaign members", alias="campaignMembers"
    )
    actors: Optional[Sequence[Actor]] = Field(
        None, description="List of actors associated with the campaign"
    )
    malware: Optional[Sequence[Malware]] = Field(
        None, description="List of malware families associated with the campaign"
    )
    techniques: Optional[Sequence[Technique]] = Field(
        None, description="List of techniques used in the campaign"
    )
    notable: Optional[bool] = RecommendedField(None, description="Undocumented.")
    families: Optional[Sequence[Family]] = Field(None, description="Undocumented.")
    brands: Optional[Sequence[Any]] = RecommendedField(
        None, description="Undocumented."
    )


# TAPClient class
class TAPCampaignClient(BaseTAPClient):
    """Client to interact with the TAP Campaign API.

    Reference:
            https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Campaign_API [consulted on December 12, 2024]

    Exemples:
        >>> import asyncio
        >>> import os
        >>> from datetime import datetime, timezone
        >>> from dotenv import load_dotenv
        >>> _ = load_dotenv()
        >>> client = TAPCampaignClient(
        ...     os.environ["TAP_BASE_URL"],
        ...     os.environ["TAP_PRINCIPAL"],
        ...     os.environ["TAP_SECRET"],
        ...     int(os.environ["TAP_TIMEOUT"]),
        ...     int(os.environ["TAP_RETRY"]),
        ...     int(os.environ["TAP_BACKOFF"]),
        ... )
        >>> start_time = datetime(2023, 12, 13, tzinfo=timezone.utc)
        >>> end_time = datetime(2023, 12, 13, 12, 00, 00, tzinfo=timezone.utc)
        >>> async def use_case_get_campaigns_details(
        ...     client: TAPCampaignClient, start_time: datetime, end_time: datetime
        ... ) -> list[CampaignDetailsResponse]:
        ...     holders = []
        ...     ids_response = await client.fetch_campaign_ids(
        ...         start_time, end_time
        ...     )
        ...     for campaign in ids_response.campaigns:
        ...         campaign_id = campaign.id
        ...         details_response = await client.fetch_campaign_details(campaign_id)
        ...         holders.append(details_response)
        ...     return holders
        >>> campaigns_details = asyncio.run(
        ...     use_case_get_campaigns_details(client, start_time, end_time)
        ... )

    """

    @staticmethod
    def _format_interval_param(start_time: datetime, end_time: datetime) -> str:
        """Format the interval parameter for the query URL."""
        return f"{start_time.isoformat()}/{end_time.isoformat()}"

    def _build_campaign_ids_query(
        self,
        start_time: datetime,
        end_time: datetime,
        size: Optional[int] = None,
        page: Optional[int] = None,
    ) -> str:
        """Build the query URL for fetching campaign IDs.

        Args:
            start_time(datetime.datetime): Start time of the interval
            end_time(datetime.datetime): End time of the interval
            size (int): Number of records to fetch
            page (int): The page of results to return, in multiples of the specified size (or 100, if no size is explicitly chosen). Defaults to 1

        """
        if end_time - start_time > timedelta(hours=24):
            raise ProofpointAPIError(
                "The interval between start_time and end_time should be less than 24 hours."
            )

        interval = TAPCampaignClient._format_interval_param(start_time, end_time)

        if size is not None and size > 200:
            raise ProofpointAPIError("The maximum allowed value for size is 200.")

        query_params = {"interval": interval, "size": size, "page": page}
        # Remove None values from query_params
        query_params = {k: v for k, v in query_params.items() if v is not None}
        return self.format_get_query("/v2/campaign/ids", query_params)

    def _build_campaign_details_query(self, campaign_id: str) -> str:
        """Build the query URL for fetching campaign details.

        Args:
            campaign_id (str): The unique identifier of the campaign.

        Returns:
            str: The query URL.

        """
        return self.format_get_query(path=urljoin("/v2/campaign/", campaign_id))

    async def fetch_campaign_ids(
        self,
        start_time: datetime,
        end_time: datetime,
        page: Optional[int] = None,
        size: Optional[int] = None,
    ) -> CampaignIdsResponse:
        """Fetch the campaign IDs.

        Args:
            start_time (datetime): Start time of the interval
            end_time (datetime): End time of the interval
            page (int): The page of results to return, in multiples of the specified size (or 100, if no size is explicitly chosen). Defaults to 1
            size (int): Number of records to fetch

        Returns:
            CampaignIdsResponse: The campaign IDs response.

        """
        query_url = self._build_campaign_ids_query(start_time, end_time, page, size)
        return await self.get(query_url, CampaignIdsResponse)

    async def fetch_campaign_details(self, campaign_id: str) -> CampaignDetailsResponse:
        """Fetch the details of a campaign.

        Args:
            campaign_id (str): The unique identifier of the campaign.

        Returns:
            CampaignDetailsResponse: The campaign details.

        """
        query_url = self._build_campaign_details_query(campaign_id)
        return await self.get(query_url, response_model=CampaignDetailsResponse)
