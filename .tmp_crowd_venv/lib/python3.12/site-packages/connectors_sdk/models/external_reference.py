"""ExternalReference."""

import stix2
from connectors_sdk.models.base_object import BaseObject
from pydantic import Field


class ExternalReference(BaseObject):
    """Represents an external reference to a source of information."""

    source_name: str = Field(
        description="The name of the source of the external reference.",
    )
    description: str | None = Field(
        default=None,
        description="Description of the external reference.",
    )
    url: str | None = Field(
        default=None,
        description="URL of the external reference.",
    )
    external_id: str | None = Field(
        default=None,
        description="An identifier for the external reference content.",
    )

    def to_stix2_object(self) -> stix2.v21.ExternalReference:
        """Make stix object."""
        return stix2.ExternalReference(
            source_name=self.source_name,
            description=self.description,
            url=self.url,
            external_id=self.external_id,
        )
