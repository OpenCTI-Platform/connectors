"""Offer python client and response models for the ProofPoint TAP enriched campaign."""

import asyncio
from typing import Sequence

from pydantic import Field

from proofpoint_tap.client_api.common import BaseTAPClient
from proofpoint_tap.client_api.v2.campaign import (
    CampaignDetailsResponse,
    CampaignMember,
    TAPCampaignClient,
)
from proofpoint_tap.client_api.v2.forensics import Forensics, TAPForensicsClient
from proofpoint_tap.client_api.v2.threat import TAPThreatClient, ThreatSummary


class CampaignMemberCompiledInfo(CampaignMember, ThreatSummary):
    """Compile information about a campaign member/threat."""


class CampaignCompiledInfo(CampaignDetailsResponse):
    """Compile information about a campaign with its members and threats."""

    campaign_members: Sequence[CampaignMemberCompiledInfo] = Field(
        ..., description="List of campaign members", alias="campaignMembers"
    )
    forensics: Forensics = Field(..., description="List of forensic reports")


class TAPCompiledCampaignClient(BaseTAPClient):
    """Client to interact with the TAP API.

    Examples:
        >>> import asyncio
        >>> import os
        >>> from dotenv import load_dotenv
        >>> _ = load_dotenv()
        >>> client = TAPCompiledCampaignClient(
        ...     base_url=os.environ["TAP_BASE_URL"],
        ...     principal=os.environ["TAP_PRINCIPAL"],
        ...     secret=os.environ["TAP_SECRET"],
        ...     timeout=os.environ["TAP_TIMEOUT"],
        ...     retrty=os.environ["TAP_RETRY"],
        ...     backoff=os.environ["TAP_BACKOFF"],
        ... )
        >>> campaign_id = "90116999-337f-40e0-a25f-e17ae1d8a4f4"
        >>> results = asyncio.run(client.fetch_campaign(campaign_id))

    """

    def __init__(
        self,
        base_url: str,
        principal: str,
        secret: str,
        timeout: int,
        retry: int,
        backoff: int,
    ):
        """Initialize the client
        Args:
            base_url (str): The base URL of the TAP API.
            principal (str): The principal to authenticate with the API.
            secret (str): The secret to authenticate with the API.
            timeout (int): The timeout for the API requests in seconds.

        """
        common_kwargs = dict(  # noqa: C408  # keep dict constructor rather than literal dict for maintainance.
            base_url=base_url,
            principal=principal,
            secret=secret,
            timeout=timeout,
            retry=retry,
            backoff=backoff,
        )

        # we deserialize instead of repeating kwargs
        super().__init__(
            **common_kwargs  # type:ignore[arg-type]
        )
        self.campaign = TAPCampaignClient(**common_kwargs)  # type:ignore[arg-type]
        self.threat = TAPThreatClient(**common_kwargs)  # type:ignore[arg-type]
        self.forensics = TAPForensicsClient(**common_kwargs)  # type:ignore[arg-type]

    async def fetch_campaign(self, campaign_id: str) -> CampaignCompiledInfo:
        """Fetch the details of a campaign and compile additional information.

        Args:
            campaign_id (str): The unique identifier of the campaign.

        Returns:
            CampaignAggregatedInfo: The campaign details with additional information.

        """
        task_campaign_details = asyncio.create_task(
            self.campaign.fetch_campaign_details(campaign_id)
        )
        task_forensics = asyncio.create_task(
            self.forensics.fetch_forensics(campaign_id=campaign_id)
        )
        # Await the needed campaign details to launch threats retrieval
        campaign_details = await task_campaign_details
        tasks_threats = [
            asyncio.create_task(self.threat.fetch_threat_summary(member.id))
            for member in campaign_details.campaign_members
        ]

        # Await the threats and forensics to enrich campaign
        apis_results = await asyncio.gather(*tasks_threats, task_forensics)

        threat_summaries = apis_results[:-1]
        forensics = apis_results[-1]

        # We manipulate the description as dict to include the threat summary and forensics
        holder = campaign_details.model_dump(by_alias=True)
        for index, summary in enumerate(threat_summaries):
            holder["campaignMembers"][index].update(summary.model_dump(by_alias=True))

        holder["forensics"] = forensics.model_dump(by_alias=True)
        return CampaignCompiledInfo.model_validate(holder)
