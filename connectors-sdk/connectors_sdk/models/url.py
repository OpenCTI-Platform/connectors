"""URL."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pydantic import Field
from stix2.v21 import URL as Stix2URL  # noqa: N811 # URL is not a constant but a class


class URL(BaseObservableEntity):
    """Represent a URL observable."""

    value: str = Field(
        description="The URL value.",
        min_length=1,
    )

    def to_stix2_object(self) -> Stix2URL:
        """Make stix object."""
        return Stix2URL(
            value=self.value,
            **self._common_stix2_properties(),
        )
