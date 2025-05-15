"""The module defines the IPv6AddressModel class, which represents a STIX 2.1 IPv6 Address object."""

from typing import List, Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import IPv6Address, _STIXBase21  # type: ignore


class IPv6AddressModel(BaseSCOModel):
    """Model representing an IPv6 Address in STIX 2.1 format."""

    value: str = Field(
        ...,
        description="One or more IPv6 addresses expressed in CIDR notation (e.g., '2001:db8::1/64'). /128 MAY be omitted for single addresses.",
    )

    resolves_to_refs: Optional[List[str]] = Field(
        default=None,
        description="(Deprecated) References to MAC address objects this IPv6 resolves to. MUST be of type 'mac-addr'.",
    )

    belongs_to_refs: Optional[List[str]] = Field(
        default=None,
        description="(Deprecated) References to autonomous system objects this IPv6 belongs to. MUST be of type 'autonomous-system'.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return IPv6Address(**self.model_dump(exclude_none=True))


def test_ipv6_address_model() -> None:
    """Test function to demonstrate the usage of IPv6AddressModel."""
    from uuid import uuid4

    # === Minimal IPv6 ===
    minimal = IPv6AddressModel(
        type="ipv6-addr",
        spec_version="2.1",
        id=f"ipv6-addr--{uuid4()}",
        value="2001:db8::dead:beef",
    )

    print("=== MINIMAL IPV6 ADDRESS ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full IPv6 ===
    full = IPv6AddressModel(
        type="ipv6-addr",
        spec_version="2.1",
        id=f"ipv6-addr--{uuid4()}",
        value="2001:db8:abcd:0012::0/64",
        resolves_to_refs=[f"mac-addr--{uuid4()}"],
        belongs_to_refs=[f"autonomous-system--{uuid4()}"],
    )

    print("\n=== FULL IPV6 ADDRESS ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_ipv6_address_model()
