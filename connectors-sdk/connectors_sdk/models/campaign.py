"""Campaign."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from pycti import Campaign as PyctiCampaign
from pydantic import AwareDatetime, Field
from stix2.v21 import Campaign as Stix2Campaign


class Campaign(BaseIdentifiedEntity):
    """Define a Campaign on OpenCTI."""

    name: str = Field(
        description="A name used to identify this Campaign.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="A description that provides more details and context about the Campaign.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Alternative names used to identify this Campaign.",
    )
    first_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Campaign was first seen.",
    )
    last_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Campaign was last seen.",
    )
    objective: str | None = Field(
        default=None,
        description="The objective of this Campaign.",
    )

    def to_stix2_object(self) -> Stix2Campaign:
        """Make stix object."""
        return Stix2Campaign(
            id=PyctiCampaign.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            objective=self.objective,
            **self._common_stix2_properties()
        )
