"""Hostname."""

from connectors_sdk.models.base_custom_observable_entity import (
    BaseCustomObservableEntity,
)
from pycti import CustomObservableHostname
from pydantic import Field


class Hostname(BaseCustomObservableEntity):
    """Define a Hostname observable on OpenCTI.

    Examples:
        >>> hostname = Hostname(
        ...     value="example.com",
        ...     )
        >>> entity = hostname.to_stix2_object()
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
