"""IpV4."""

import ipaddress

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
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

    Notes:
        - The `resolves_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `resolves-to` relationships.
        - The `belongs_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `belongs-to` relationships.
    """

    value: str = Field(
        description="The IP address value. CIDR is allowed.",
        min_length=1,
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
            **self._common_stix2_properties(),
        )
