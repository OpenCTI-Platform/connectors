"""Offer python client and response models for the TAP Forensic API."""

from typing import Any, List, Literal, Optional, Union

import aiohttp
from pydantic import AwareDatetime, Field, model_validator

from proofpoint_tap.client_api.common import BaseTAPClient
from proofpoint_tap.errors import ProofpointAPIError
from proofpoint_tap.warnings import (
    BaseModelWithRecommendedFieldAndExtraWarning,
    RecommendedField,
)


class Platform(BaseModelWithRecommendedFieldAndExtraWarning):
    """Platform object that represents the environment in which the evidence was observed."""

    name: str = Field(
        ..., description="Name of the platform (e.g., Windows XP, Android)"
    )
    os: Optional[str] = RecommendedField(
        None, description="Operating system associated with the platform"
    )
    version: str = Field(..., description="Version of the platform")


class Attachment(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for attachment-related indicators."""

    sha256: Optional[str] = Field(
        None, description="SHA256 hash of the attachment's contents"
    )
    blacklisted: Optional[int] = Field(
        None, description="Whether the file was blocklisted"
    )
    md5: Optional[str] = Field(
        None, description="MD5 hash of the attachment's contents"
    )
    offset: Optional[int] = Field(
        None, description="Offset where malicious content was found"
    )
    rule: Optional[str] = Field(
        None, description="Static rule name that identified the malicious content"
    )
    size: Optional[int] = Field(None, description="Size of the attachment in bytes")


class Behavior(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for behavior-related indicators."""

    rule: str = Field(..., description="Name of the rule that identified the behavior")
    url: Optional[str] = Field(None, description="URL associated with the behavior")


class Cookie(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for cookie-related indicators."""

    action: str = Field(
        ..., description="Action performed on the cookie (set or deleted)"
    )
    domain: str = Field(..., description="Domain that set or deleted the cookie")
    key: str = Field(..., description="The name of the cookie")
    value: Optional[str] = Field(None, description="Content of the cookie (if set)")


class DNS(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for DNS-related indicators."""

    host: str = Field(..., description="The hostname being resolved")
    cnames: Optional[List[str]] = Field(
        None, description="CNAMEs associated with the hostname"
    )
    ips: Optional[List[str]] = Field(
        None, description="IP addresses resolved to the hostname"
    )
    nameservers: Optional[List[str]] = Field(
        None, description="Nameservers for the domain"
    )
    nameservers_list: Optional[List[str]] = Field(
        None, description="List of nameservers"
    )


class Dropper(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for dropper-related indicators."""

    path: str = Field(..., description="Path where the dropper file was found")
    rule: Optional[str] = Field(
        None, description="Static rule name that identified the dropper"
    )
    url: Optional[str] = Field(None, description="URL the dropper contacted")


class File(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for file-related indicators."""

    action: Optional[str] = Field(
        None, description="File system action (create, modify, or delete)"
    )
    md5: Optional[str] = Field(None, description="MD5 hash of the file")
    path: Optional[str] = Field(None, description="Path of the file that was modified")
    rule: Optional[str] = Field(
        None, description="Static rule name that identified the suspicious file"
    )
    sha256: Optional[str] = Field(None, description="SHA256 hash of the file")
    size: Optional[int] = Field(None, description="Size of the file in bytes")


class IDSRule(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for IDS-related indicators."""

    name: str = Field(..., description="Friendly name of the IDS rule")
    signature_id: int = Field(..., description="Signature ID of the IDS rule")


class Mutex(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for mutex-related indicators."""

    name: str = Field(..., description="Name of the mutex created")
    path: Optional[str] = Field(
        None, description="Path to the process that created the mutex"
    )


class Network(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for network-related indicators."""

    action: Literal["connect", "listen"] = Field(
        ..., description="Type of network activity (connect or listen)"
    )
    ip: str = Field(..., description="Remote IP address being contacted")
    port: int = Field(..., description="Remote port being contacted")
    type: str = Field(..., description="Protocol used (e.g., tcp or udp)")


class Process(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for process-related indicators."""

    path: str = Field(
        ..., description="Path to the executable that launched the process"
    )
    action: str = Field(
        ..., description="Action performed on the process (currently only 'create')"
    )


class Registry(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for registry-related indicators."""

    action: str = Field(..., description="Action on the registry (create or set)")
    key: str = Field(..., description="Path to the registry key being modified")
    name: Optional[str] = Field(None, description="Name of the registry entry")
    rule: Optional[str] = Field(
        None, description="Static rule name that identified the registry modification"
    )
    value: Optional[str] = Field(
        None, description="Value being set or created in the registry"
    )


class Screenshot(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for screenshot-related indicators."""

    url: str = Field(..., description="URL of the screenshot image")


class URL(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence type for URL-related indicators."""

    url: str = Field(..., description="URL that was visited")
    blacklisted: Optional[bool] = Field(
        None, description="Whether the URL is blocklisted"
    )
    ip: Optional[str] = Field(None, description="IP address resolved for the URL")
    http_status: Optional[int] = Field(
        None, description="HTTP status code returned by the URL"
    )
    md5: Optional[str] = Field(
        None, description="MD5 hash of the file downloaded from the URL"
    )
    offset: Optional[int] = Field(None, description="Offset where the URL was found")
    rule: Optional[str] = Field(
        None, description="Static rule name that identified the URL"
    )
    sha256: Optional[str] = Field(None, description="SHA256 hash of the file")
    size: Optional[int] = Field(
        None, description="Size of the file downloaded from the URL"
    )


class Evidence(BaseModelWithRecommendedFieldAndExtraWarning):
    """Evidence object corresponding to a detected marker or indicator of compromise."""

    type: str = Field(
        ..., description="The type of evidence detected (e.g., 'attachment', 'url')"
    )
    display: str = Field(
        ..., description="A user-friendly display string for the evidence"
    )
    malicious: Optional[bool] = Field(
        None,
        description="Indicates whether the evidence was determined to be malicious.",
    )
    time: int = Field(..., description="Timestamp (unsupported; always returns '0')")
    what: Union[
        Attachment,
        Behavior,
        Cookie,
        DNS,
        Dropper,
        File,
        IDSRule,
        Mutex,
        Network,
        Process,
        Registry,
        Screenshot,
        URL,
    ] = Field(..., description="Map of values specific to the evidence type")
    platforms: List[Platform] = Field(
        ..., description="List of platforms where this evidence was observed"
    )
    engine: Optional[str] = RecommendedField(
        ..., description="Engine that detected the evidence"
    )
    note: Optional[str] = Field(None, description="Additional note about the evidence")

    @model_validator(mode="before")
    @classmethod
    def _what_field_selector(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Validate and cast the `what` field to the correct model."""
        evidence_type = str(values.get("type", "")).lower()
        what_data = values.get("what")
        if not evidence_type or not what_data:
            raise ValueError("'type' and 'what' fields are required.")

        evidence_type_mapping = {
            "attachment": Attachment,
            "behavior": Behavior,
            "cookie": Cookie,
            "dns": DNS,
            "dropper": Dropper,
            "file": File,
            "idsrule": IDSRule,
            "mutex": Mutex,
            "network": Network,
            "process": Process,
            "registry": Registry,
            "screenshot": Screenshot,
            "url": URL,
        }

        model = evidence_type_mapping.get(evidence_type)
        if not model:
            # Post validator will cast ValueError to pydantic.ValidationError
            raise ValueError(f"Unsupported evidence type: {evidence_type}")

        # Validate and cast `what` field to the correct model
        values["what"] = model(**what_data)
        return values


class Report(BaseModelWithRecommendedFieldAndExtraWarning):
    """A report object containing details about a specific threat or campaign."""

    name: str = Field(
        ..., description="The malicious URL, SHA256 hash, or campaign name"
    )
    scope: str = Field(
        ..., description="The scope of the report, either 'campaign' or 'threat'"
    )
    type: Optional[str] = Field(
        None,
        description="The type of threat (e.g., 'attachment', 'url'), it seems to be deprecated because not returned by the API anymore.",
    )
    id: str = Field(..., description="Unique identifier for the campaign or threat")
    evidences: List[Evidence] = Field(
        ...,
        description="List of evidence objects associated with this report",
        alias="forensics",
    )
    threat_status: Optional[Literal["active", "cleared", "falsePositive"]] = Field(
        None,
        description="Status of the threat. Present if request uses threatId params",
        alias="threatStatus",
    )


class Forensics(BaseModelWithRecommendedFieldAndExtraWarning):
    """Response format for the aggregate forensics."""

    generated: AwareDatetime = Field(
        ..., description="Timestamp of when the report was generated"
    )
    reports: List[Report] = Field(
        ..., description="List of reports containing forensic data"
    )


class TAPForensicsClient(BaseTAPClient):
    """Client for the Proofpoint TAP Forensics API.

    Reference:
        https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/Forensics_API [consulted on December 12, 2024]

    Examples:
        >>> import asyncio
        >>> import os
        >>> from dotenv import load_dotenv
        >>> _ = load_dotenv()
        >>> client = TAPForensicsClient(
        ...     base_url=os.environ["TAP_BASE_URL"],
        ...     principal=os.environ["TAP_PRINCIPAL"],
        ...     secret=os.environ["TAP_SECRET"],
        ...     timeout=int(os.environ["TAP_TIMEOUT"]),
        ...     retry=int(os.environ["TAP_RETRY"]),
        ...     backoff=int(os.environ["TAP_BACKOFF"]),
        ... )
        >>> forensics_from_threat = asyncio.run(
        ...     client.fetch_forensics(
        ...         threat_id="985e627c4f19c0aa9f140641b127c51674b7d4e9cf5d769842458dd23fb806ba"
        ...     )
        ... )
        >>> forensics_from_campaign = asyncio.run(
        ...     client.fetch_forensics(
        ...         campaign_id="90116999-337f-40e0-a25f-e17ae1d8a4f4"
        ...     )

    """

    def _build_forensics_query(
        self,
        threat_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        include_campaign_forensics: Optional[bool] = None,
    ) -> str:
        if not ((threat_id is not None) ^ (campaign_id is not None)):  # XOR
            raise ProofpointAPIError(
                "Exactly one of 'threat_id' or 'campaign_id' must be provided."
            )

        if threat_id is not None:
            if include_campaign_forensics is None:
                include_campaign_forensics = False

        if campaign_id is not None and include_campaign_forensics is not None:
            raise ProofpointAPIError(
                "The 'include_campaign_forensics' parameter is only valid when querying by threat ID."
            )

        query_params = {
            "threatId": threat_id,
            "campaignId": campaign_id,
            "includeCampaignForensics": include_campaign_forensics,
        }
        query_params = {k: v for k, v in query_params.items() if v is not None}

        return self.format_get_query("/v2/forensics", params=query_params)

    async def fetch_forensics(
        self,
        threat_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        include_campaign_forensics: Optional[bool] = None,
    ) -> Forensics:
        """Fetch the forensic data for a given threat or campaign.

        Args:
            threat_id (str, optional): The unique identifier of the threat.
            campaign_id (str, optional): The unique identifier of the campaign.
            include_campaign_forensics (bool, optional): Whether to include campaign forensics.

        Returns:
            Forensics: The forensic data for the given threat or campaign.

        """
        url = self._build_forensics_query(
            threat_id=threat_id,
            campaign_id=campaign_id,
            include_campaign_forensics=include_campaign_forensics,
        )
        return await self.get(url, response_model=Forensics)
