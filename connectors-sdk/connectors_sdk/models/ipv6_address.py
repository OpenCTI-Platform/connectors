"""IPV6Address."""

import ipaddress

from connectors_sdk.models.autonomous_system import AutonomousSystem
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.mac_address import MACAddress
from connectors_sdk.models.reference import Reference
from pydantic import Field, field_validator
from stix2.v21 import IPv6Address as Stix2IPv6Address


class IPV6Address(BaseObservableEntity):
    """Define an IP V6 address observable on OpenCTI.

    Examples:
        >>> ip = IPV6Address(
        ...     value="b357:5b10:0f48:d182:0140:494c:8fe9:6eda",
        ...     create_indicator=True,
        ...     )
        >>> entity = ip.to_stix2_object()
    """

    value: str = Field(
        description="The IP address value. CIDR is allowed.",
        min_length=1,
    )
    resolves_to: list[MACAddress | Reference] | None = Field(
        description="List of MAC addresses that this IP V6 address resolves to.",
        default=None,
    )
    belongs_to: list[AutonomousSystem | Reference] | None = Field(
        description="List of autonomous systems that this IP V6 address belongs to.",
        default=None,
    )

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: str) -> str:
        """Validate the value of the IP V6 address."""
        try:
            ipaddress.ip_network(
                value, strict=False
            )  # strict=False allows CIDR notation
        except ValueError:
            raise ValueError(f"Invalid IP V6 address {value}") from None
        return value

    def to_stix2_object(self) -> Stix2IPv6Address:
        """Make stix object."""
        return Stix2IPv6Address(
            value=self.value,
            resolves_to_refs=(
                [obj.id for obj in self.resolves_to] if self.resolves_to else None
            ),
            belongs_to_refs=(
                [obj.id for obj in self.belongs_to] if self.belongs_to else None
            ),
            **self._common_stix2_properties(),
        )
