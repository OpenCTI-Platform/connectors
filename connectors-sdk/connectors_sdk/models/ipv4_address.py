"""IpV4."""

import ipaddress

from connectors_sdk.models.autonomous_system import AutonomousSystem
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.mac_address import MACAddress
from connectors_sdk.models.reference import Reference
from pydantic import Field, field_validator
from stix2.v21 import IPv4Address as Stix2IPv4Address


class IPV4Address(BaseObservableEntity):
    """Define an IP V4 address observable on OpenCTI.

    Examples:
        >>> ip = IPV4Address(
        ...     value="127.0.0.1/24",
        ...     create_indicator=True,
        ...     )
        >>> entity = ip.to_stix2_object()
    """

    value: str = Field(
        description="The IP address value. CIDR is allowed.",
        min_length=1,
    )
    resolves_to: list[MACAddress | Reference] | None = Field(
        description="List of MAC addresses that this IP V4 address resolves to.",
        default=None,
    )
    belongs_to: list[AutonomousSystem | Reference] | None = Field(
        description="List of autonomous systems (AS objects) that this IP V4 address belongs to.",
        default=None,
    )

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: str) -> str:
        """Validate the value of the IP V4 address."""
        try:
            ipaddress.ip_network(
                value, strict=False
            )  # strict=False allows CIDR notation
        except ValueError:
            raise ValueError(f"Invalid IP V4 address {value}") from None
        return value

    def to_stix2_object(self) -> Stix2IPv4Address:
        """Make stix object."""
        return Stix2IPv4Address(
            value=self.value,
            resolves_to_refs=(
                [obj.id for obj in self.resolves_to] if self.resolves_to else None
            ),
            belongs_to_refs=(
                [obj.id for obj in self.belongs_to] if self.belongs_to else None
            ),
            **self._common_stix2_properties(),
        )
