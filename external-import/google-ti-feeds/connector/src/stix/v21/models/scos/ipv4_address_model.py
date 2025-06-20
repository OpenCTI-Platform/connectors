"""The module defines the IPv4AddressModel class, which represents a STIX 2.1 IPv4 Address object."""

from typing import List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    IPv4Address,
    _STIXBase21,
)


class IPv4AddressModel(BaseSCOModel):
    """Model representing an IPv4 Address in STIX 2.1 format."""

    value: str = Field(
        ...,
        description="IPv4 address or CIDR block (e.g., '192.168.1.1' or '10.0.0.0/24'). MUST conform to CIDR notation.",
    )

    resolves_to_refs: Optional[List[str]] = Field(
        default=None,
        description="(Deprecated) List of MAC address object references this IP resolves to. MUST be of type 'mac-addr'.",
    )

    belongs_to_refs: Optional[List[str]] = Field(
        default=None,
        description="(Deprecated) List of autonomous-system object references this IP belongs to. MUST be of type 'autonomous-system'.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return IPv4Address(**self.model_dump(exclude_none=True))
