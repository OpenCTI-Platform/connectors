"""IntrusionSet."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import (
    AttackMotivation,
    AttackResourceLevel,
)
from pycti import IntrusionSet as PyctiIntrusionSet
from pydantic import AwareDatetime, Field
from stix2.v21 import IntrusionSet as Stix2IntrusionSet


class IntrusionSet(BaseIdentifiedEntity):
    """Define an Intrusion Set on OpenCTI."""

    name: str = Field(
        description="A name used to identify this Intrusion Set.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="A description that provides more details and context about the Intrusion Set.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Alternative names used to identify this Intrusion Set.",
    )
    first_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Intrusion Set was first seen.",
    )
    last_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Intrusion Set was last seen.",
    )
    goals: list[str] | None = Field(
        default=None,
        description="The high-level goals of this Intrusion Set, namely, what are they trying to do.",
    )
    resource_level: AttackResourceLevel | None = Field(
        default=None,
        description="The organizational level at which this Intrusion Set typically works.",
    )
    primary_motivation: AttackMotivation | None = Field(
        default=None,
        description="The primary reason, motivation, or purpose behind this Intrusion Set.",
    )
    secondary_motivations: list[AttackMotivation] | None = Field(
        default=None,
        description="The secondary reasons, motivations, or purposes behind this Intrusion Set.",
    )

    def to_stix2_object(self) -> Stix2IntrusionSet:
        """Make stix object."""
        return Stix2IntrusionSet(
            id=PyctiIntrusionSet.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            goals=self.goals,
            resource_level=self.resource_level,
            primary_motivation=self.primary_motivation,
            secondary_motivations=self.secondary_motivations,
            **self._common_stix2_properties()
        )
