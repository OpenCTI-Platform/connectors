"""MACAddress."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pydantic import Field
from stix2.v21 import MACAddress as Stix2MACAddress


class MACAddress(BaseObservableEntity):
    """Represent a MAC address observable on OpenCTI."""

    value: str = Field(
        description="The MAC address value.",
        min_length=1,
    )

    def to_stix2_object(self) -> Stix2MACAddress:
        """Make stix object."""
        return Stix2MACAddress(
            value=self.value,
            **self._common_stix2_properties(),
        )
