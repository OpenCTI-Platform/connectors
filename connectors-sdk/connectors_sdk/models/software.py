"""Software."""

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pydantic import Field
from stix2.v21 import Software as Stix2Software


class Software(BaseObservableEntity):
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
            **self._common_stix2_properties()
        )
