"""URL."""

from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models._observable import Observable
from pydantic import Field
from stix2.v21 import URL as Stix2URL  # noqa: N811 # URL is not a constant but a class


@MODEL_REGISTRY.register
class URL(Observable):
    """Represent a URL observable."""

    value: str = Field(
        description="The URL value.",
        min_length=1,
    )

    def to_stix2_object(self) -> Stix2URL:
        """Make stix object."""
        return Stix2URL(
            value=self.value,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            **self._custom_properties_to_stix(),
        )
