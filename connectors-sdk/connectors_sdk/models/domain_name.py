"""DomainName."""

from typing import TYPE_CHECKING

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pydantic import Field
from stix2.v21 import DomainName as Stix2DomainName

if TYPE_CHECKING:
    from connectors_sdk.models.ipv4_address import IPV4Address
    from connectors_sdk.models.ipv6_address import IPV6Address
    from connectors_sdk.models.reference import Reference


class DomainName(BaseObservableEntity):
    """Define a domain name observable on OpenCTI."""

    value: str = Field(
        description="Specifies the value of the domain name.",
        min_length=1,
    )
    resolves_to: "list[IPV4Address | IPV6Address | DomainName | Reference] | None" = (
        Field(
            description="List of IP addresses or domain names that this domain name resolves to.",
            default=None,
        )
    )

    def to_stix2_object(self) -> Stix2DomainName:
        """Make stix object."""
        return Stix2DomainName(
            value=self.value,
            resolves_to_refs=(
                [obj.id for obj in self.resolves_to] if self.resolves_to else None
            ),
            **self._common_stix2_properties(),
        )
