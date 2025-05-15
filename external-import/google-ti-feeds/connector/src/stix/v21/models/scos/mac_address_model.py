"""The module defines the MACAddressModel class, which represents a STIX 2.1 MAC Address object."""

import re

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field, field_validator
from stix2.v21 import MACAddress, _STIXBase21  # type: ignore


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


def test_mac_address_model() -> None:
    """Test function to demonstrate the usage of MACAddressModel."""
    from uuid import uuid4

    # === Minimal MAC Address ===
    minimal = MACAddressModel(
        type="mac-addr",
        spec_version="2.1",
        id=f"mac-addr--{uuid4()}",
        value="00:0a:95:9d:68:16",
    )

    print("=== MINIMAL MAC ADDRESS ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full MAC Address ===
    full = MACAddressModel(
        type="mac-addr",
        spec_version="2.1",
        id=f"mac-addr--{uuid4()}",
        value="de:ad:be:ef:00:01",
    )

    print("\n=== FULL MAC ADDRESS ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_mac_address_model()
