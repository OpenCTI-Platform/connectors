"""DomainName."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.ipv4_address import (  # pylint: disable=unused-import # actually used during model_rebuild
    IPV4Address,
)
from connectors_sdk.models.ipv6_address import (  # pylint: disable=unused-import # actually used during model_rebuild
    IPV6Address,
)
from connectors_sdk.models.reference import (  # pylint: disable=unused-import # actually used during model_rebuild
    Reference,
)
from pydantic import Field
from stix2.v21 import DomainName as Stix2DomainName


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


# Rebuilding the model is required to resolve forward reference to DomainName used in `resolves_to`.
# Without this, isolated executions (e.g. a single test module) can fail due to
# "DomainName is not fully defined" error before any instance validation/conversion.
DomainName.model_rebuild()
