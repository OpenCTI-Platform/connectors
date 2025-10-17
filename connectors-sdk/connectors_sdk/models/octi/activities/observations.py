"""Offer observations OpenCTI entities."""

from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models._observable import Observable
from pydantic import Field
from stix2.v21 import URL as Stix2URL  # noqa: N811 # URL is not a constant but a class
from stix2.v21 import Software as Stix2Software


@MODEL_REGISTRY.register
class Software(Observable):
    """Represents a software observable."""

    name: str = Field(
        description="Name of the software.",
        min_length=1,
    )
    version: str | None = Field(
        default=None,
        description="Version of the software.",
    )
    vendor: str | None = Field(
        default=None,
        description="Vendor of the software.",
    )
    swid: str | None = Field(
        default=None,
        description="SWID of the software.",
    )
    cpe: str | None = Field(
        default=None,
        description="CPE of the software.",
    )
    languages: list[str] | None = Field(
        default=None,
        description="Languages of the software.",
    )

    def to_stix2_object(self) -> Stix2Software:
        """Make Software STIX2.1 object."""
        return Stix2Software(
            name=self.name,
            version=self.version,
            vendor=self.vendor,
            swid=self.swid,
            cpe=self.cpe,
            languages=self.languages,
            object_marking_refs=[marking.id for marking in self.markings or []],
            allow_custom=True,
            **self._custom_properties_to_stix(),
        )


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


MODEL_REGISTRY.rebuild_all()
