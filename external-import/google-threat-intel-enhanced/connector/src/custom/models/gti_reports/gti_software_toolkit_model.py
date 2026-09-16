"""Model representing a Google Threat Intelligence Software Toolkit."""

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class AltNameDetail(BaseModel):
    """Alternative names/aliases by which the software toolkit could be known."""

    confidence: Optional[str] = Field(
        None,
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


class Counters(BaseModel):
    """Count of related entities for the software toolkit."""

    domains: Optional[int] = Field(
        None, description="Number of domains related to the software toolkit."
    )
    files: Optional[int] = Field(
        None, description="Number of files related to the software toolkit."
    )
    ip_addresses: Optional[int] = Field(
        None, description="Number of IP addresses related to the software toolkit."
    )
    urls: Optional[int] = Field(
        None, description="Number of URLs related to the software toolkit."
    )
    attack_techniques: Optional[int] = Field(
        None,
        description="Number of MITRE ATT&CK techniques associated with the software toolkit.",
    )


class SeenDetail(BaseModel):
    """Details about when the software toolkit was first or last seen."""

    confidence: Optional[str] = Field(
        None, description="Confidence on the information or the attribution."
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
    value: Optional[str] = Field(
        None,
        description="Date when the observation was made (YYYY-MM-DDTHH:mm:ssZ format).",
    )


class OperatingSystem(BaseModel):
    """Operating systems the software toolkit runs on."""

    confidence: Optional[str] = Field(
        None, description="The confidence of the OS association."
    )
    description: Optional[str] = Field(
        None, description="Descriptive information related to the OS."
    )
    first_seen: Optional[int] = Field(
        None, description="First time the OS was associated (UTC timestamp)."
    )
    last_seen: Optional[int] = Field(
        None, description="Last time the OS was associated (UTC timestamp)."
    )
    value: Optional[str] = Field(None, description="Operating system name.")


class TagDetail(BaseModel):
    """Tags associated with the software toolkit with additional context."""

    confidence: Optional[str] = Field(
        None, description="Confidence on the tag association to the software toolkit."
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
    value: Optional[str] = Field(None, description="Value of the tag.")


class Capability(BaseModel):
    """Capability of a software toolkit."""

    confidence: Optional[str] = Field(
        None, description="Confidence on the capability attribution."
    )
    description: Optional[str] = Field(
        None, description="Detailed description of the capability."
    )
    first_seen: Optional[int] = Field(
        None, description="First time this capability was attributed (UTC timestamp)."
    )
    last_seen: Optional[int] = Field(
        None, description="Last time this capability was attributed (UTC timestamp)."
    )
    value: str = Field(..., description="Name/label of the capability.")


class MalwareRole(BaseModel):
    """Role classification for a software toolkit (e.g., Utility, Backdoor, etc.)."""

    confidence: Optional[str] = Field(
        None, description="Confidence on the role attribution."
    )
    description: Optional[str] = Field(
        None, description="Additional information about the role."
    )
    first_seen: Optional[int] = Field(
        None, description="First time this role was attributed (UTC timestamp)."
    )
    last_seen: Optional[int] = Field(
        None, description="Last time this role was attributed (UTC timestamp)."
    )
    value: str = Field(..., description="The role classification (e.g., Utility, Backdoor).")


class SoftwareToolkitModel(BaseModel):
    """Model representing a GTI software toolkit."""

    name: str = Field(..., description="Software toolkit's name.")
    collection_type: Optional[str] = Field(
        None,
        description="Type of object; typically 'software-toolkit' or 'software_toolkit'",
    )
    creation_date: Optional[int] = Field(
        None, description="UTC timestamp of software toolkit object creation."
    )
    last_modification_date: Optional[int] = Field(
        None, description="UTC timestamp of last software toolkit update."
    )
    description: Optional[str] = Field(
        None, description="Description/context about the software toolkit."
    )
    status: Optional[str] = Field(
        None,
        description="Status of attribute computation: PENDING_RECOMPUTE or COMPUTED.",
    )
    private: Optional[bool] = Field(
        None, description="Whether the software toolkit object is private."
    )
    origin: Optional[str] = Field(
        None,
        description="Source of the information: Partner or Google Threat Intelligence.",
    )

    counters: Optional[Counters] = Field(
        None, description="Counters for related indicators and metadata."
    )
    alt_names_details: Optional[List[AltNameDetail]] = Field(
        None, description="Alternative names/aliases for the software toolkit."
    )
    first_seen_details: Optional[List[SeenDetail]] = Field(
        None, description="Information about when the software toolkit was first seen."
    )
    last_seen_details: Optional[List[SeenDetail]] = Field(
        None, description="Information about when the software toolkit was last seen."
    )
    operating_systems: Optional[List[OperatingSystem]] = Field(
        None, description="Operating systems the software toolkit runs on."
    )
    tags_details: Optional[List[TagDetail]] = Field(
        None, description="Tags applied to the software toolkit, with context."
    )
    capabilities: Optional[List[Capability]] = Field(
        None, description="Capabilities of the software toolkit."
    )
    malware_roles: Optional[List[MalwareRole]] = Field(
        None, description="Role classifications for the software toolkit (e.g., Utility)."
    )


class GTISoftwareToolkitData(BaseModel):
    """Model representing data for a GTI software toolkit."""

    id: str
    type: Optional[str] = None
    links: Optional[Dict[str, str]] = None
    attributes: Optional[SoftwareToolkitModel] = None
    context_attributes: Optional[Dict[str, Any]] = None


class GTISoftwareToolkitMeta(BaseModel):
    """Model representing metadata for GTI software toolkit responses."""

    count: Optional[int] = None
    cursor: Optional[str] = None


class GTISoftwareToolkitResponse(BaseModel):
    """Model representing a response containing GTI software toolkit data."""

    data: Union[GTISoftwareToolkitData, List[GTISoftwareToolkitData]]
    meta: Optional[GTISoftwareToolkitMeta] = None
