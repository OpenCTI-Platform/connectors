"""Text."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pycti import CustomObservableText
from pydantic import Field


class Text(BaseObservableEntity):
    """Represent a Text observable on OpenCTI.

    Examples:
        >>> text = Text(value="some extracted config value")
        >>> entity = text.to_stix2_object()
    """

    value: str = Field(
        description="The text value.",
        min_length=1,
    )

    def to_stix2_object(self) -> CustomObservableText:
        """Make stix object."""
        return CustomObservableText(
            value=self.value,
            **self._common_stix2_properties(),
        )
