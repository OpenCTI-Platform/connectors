"""The module defines the MACAddressModel class, which represents a STIX 2.1 MAC Address object."""

import re

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field, field_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    MACAddress,
    _STIXBase21,
)


class MACAddressModel(BaseSCOModel):
    """Model representing a MAC Address in STIX 2.1 format."""

    value: str = Field(
        ...,
        description="A single colon-delimited, lowercase MAC-48 address with leading zeros (e.g., 00:00:ab:cd:ef:01).",
    )

    @field_validator("value")
    @classmethod
    def validate_mac_format(cls, v: str) -> str:
        """Validate the MAC address format."""
        pattern = r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$"
        if not re.fullmatch(pattern, v):
            raise ValueError(
                "MAC address must be colon-delimited, lowercase, and include leading zeros (e.g., 00:00:ab:cd:ef:01)."
            )
        return v

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return MACAddress(**self.model_dump(exclude_none=True))
