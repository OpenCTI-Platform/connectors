"""DomainName."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pydantic import Field
from stix2.v21 import DomainName as Stix2DomainName


class DomainName(BaseObservableEntity):
    """Define a domain name observable on OpenCTI.

    Notes:
        - The `resolves_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `resolves-to` relationships.

    """

    value: str = Field(
        description="Specifies the value of the domain name.",
        min_length=1,
    )

    def to_stix2_object(self) -> Stix2DomainName:
        """Make stix object."""
        return Stix2DomainName(
            value=self.value,
            **self._common_stix2_properties(),
        )
