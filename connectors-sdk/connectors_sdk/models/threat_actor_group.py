"""ThreatActorGroup."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import (
    AttackMotivation,
    AttackResourceLevel,
    ThreatActorRole,
    ThreatActorSophistication,
    ThreatActorTypes,
)
from pycti import ThreatActorGroup as PyctiThreatActorGroup
from pydantic import AwareDatetime, Field
from stix2.v21 import ThreatActor as Stix2ThreatActor


class ThreatActorGroup(BaseIdentifiedEntity):
    """Define a Threat Actor (group) on OpenCTI."""

    name: str = Field(
        description="A name used to identify this Threat Actor.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="A description that provides more details and context about the Threat Actor.",
    )
    threat_actor_types: list[ThreatActorTypes] | None = Field(
        default=None,
        description="The type(s) of this threat actor.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Alternative names used to identify this Threat Actor.",
    )
    first_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Threat Actor was first seen.",
    )
    last_seen: AwareDatetime | None = Field(
        default=None,
        description="The time that this Threat Actor was last seen.",
    )
    roles: list[ThreatActorRole] | None = Field(
        default=None,
        description="A list of roles the Threat Actor plays.",
    )
    goals: list[str] | None = Field(
        default=None,
        description="The high-level goals of this Threat Actor, namely, what are they trying to do.",
    )
    sophistication: ThreatActorSophistication | None = Field(
        default=None,
        description="The skill, specific knowledge, special training, or expertise a Threat Actor must have to perform the attack.",
    )
    resource_level: AttackResourceLevel | None = Field(
        default=None,
        description="The organizational level at which this Threat Actor typically works.",
    )
    primary_motivation: AttackMotivation | None = Field(
        default=None,
        description="The primary reason, motivation, or purpose behind this Threat Actor.",
    )
    secondary_motivations: list[AttackMotivation] | None = Field(
        default=None,
        description="The secondary reasons, motivations, or purposes behind this Threat Actor.",
    )
    personal_motivations: list[AttackMotivation] | None = Field(
        default=None,
        description="The personal reasons, motivations, or purposes of the Threat Actor regardless of organizational goals.",
    )

    def to_stix2_object(self) -> Stix2ThreatActor:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Threat Actor SDO to OCTI Threat Actor Group entity based on its `id`.
            - To create an Threat Actor Group on OpenCTI, `id` MUST be generated thanks to `PyctiThreatActorGroup.generate_id` method.
        """
        return Stix2ThreatActor(
            id=PyctiThreatActorGroup.generate_id(name=self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            goals=self.goals,
            sophistication=self.sophistication,
            resource_level=self.resource_level,
            primary_motivation=self.primary_motivation,
            secondary_motivations=self.secondary_motivations,
            personal_motivations=self.personal_motivations,
            **self._common_stix2_properties()
        )
