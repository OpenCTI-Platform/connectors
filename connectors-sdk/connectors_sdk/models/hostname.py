"""Hostname."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pycti import CustomObservableHostname
from pydantic import Field


class Hostname(BaseObservableEntity):
    """Define a Hostname observable on OpenCTI.

    Examples:
        >>> hostname = Hostname(
        ...     value=""
        ...     create_indicator=True,
        ...     )
        >>> entity = hostname.to_stix2_object()

    Notes:
        - The `resolves_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `resolves-to` relationships.
        - The `belongs_to_refs` (from STIX2.1 spec) field is not implemented on OpenCTI.
          It must be replaced by explicit `belongs-to` relationships.
    """

    value: str = Field(
        description="The Hostname value.",
        min_length=1,
    )

    def to_stix2_object(self) -> CustomObservableHostname:
        """Make stix object."""
        return CustomObservableHostname(
            value=self.value,
            **self._common_stix2_properties(),
        )
