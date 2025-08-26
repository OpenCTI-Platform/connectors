"""Offer threats OpenCTI entities."""

from typing import Optional

from connectors_sdk.models.octi._common import MODEL_REGISTRY, BaseIdentifiedEntity
from connectors_sdk.models.octi.enums import (
    AttackMotivation,
    AttackResourceLevel,
    ThreatActorRole,
    ThreatActorSophistication,
    ThreatActorTypes,
)
from pycti import IntrusionSet as PyctiIntrusionSet
from pycti import ThreatActorGroup as PyctiThreatActorGroup
from pydantic import AwareDatetime, Field
from stix2.v21 import IntrusionSet as Stix2IntrusionSet
from stix2.v21 import ThreatActor as Stix2ThreatActor


@MODEL_REGISTRY.register
class IntrusionSet(BaseIdentifiedEntity):
    """Define an Intrusion Set on OpenCTI."""

    name: str = Field(
        description="A name used to identify this Intrusion Set.",
        min_length=1,
    )
    description: Optional[str] = Field(
        description="A description that provides more details and context about the Intrusion Set.",
        default=None,
    )
    aliases: Optional[list[str]] = Field(
        description="Alternative names used to identify this Intrusion Set.",
        default=None,
    )
    first_seen: Optional[AwareDatetime] = Field(
        description="The time that this Intrusion Set was first seen.",
        default=None,
    )
    last_seen: Optional[AwareDatetime] = Field(
        description="The time that this Intrusion Set was last seen.",
        default=None,
    )
    goals: Optional[list[str]] = Field(
        description="The high-level goals of this Intrusion Set, namely, what are they trying to do.",
        default=None,
    )
    resource_level: Optional[AttackResourceLevel] = Field(
        description="The organizational level at which this Intrusion Set typically works.",
        default=None,
    )
    primary_motivation: Optional[AttackMotivation] = Field(
        description="The primary reason, motivation, or purpose behind this Intrusion Set.",
        default=None,
    )
    secondary_motivations: Optional[list[AttackMotivation]] = Field(
        description="The secondary reasons, motivations, or purposes behind this Intrusion Set.",
        default=None,
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
            created_by_ref=self.author.id if self.author else None,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
        )


@MODEL_REGISTRY.register
class ThreatActorGroup(BaseIdentifiedEntity):
    """Define a Threat Actor (group) on OpenCTI."""

    name: str = Field(
        description="A name used to identify this Threat Actor.",
        min_length=1,
    )
    description: Optional[str] = Field(
        description="A description that provides more details and context about the Threat Actor.",
        default=None,
    )
    threat_actor_types: Optional[list[ThreatActorTypes]] = Field(
        description="The type(s) of this threat actor.",
        default=None,
    )
    aliases: Optional[list[str]] = Field(
        description="Alternative names used to identify this Threat Actor.",
        default=None,
    )
    first_seen: Optional[AwareDatetime] = Field(
        description="The time that this Threat Actor was first seen.",
        default=None,
    )
    last_seen: Optional[AwareDatetime] = Field(
        description="The time that this Threat Actor was last seen.",
        default=None,
    )
    roles: Optional[list[ThreatActorRole]] = Field(
        description="A list of roles the Threat Actor plays.",
        default=None,
    )
    goals: Optional[list[str]] = Field(
        description="The high-level goals of this Threat Actor, namely, what are they trying to do.",
        default=None,
    )
    sophistication: Optional[ThreatActorSophistication] = Field(
        description="The skill, specific knowledge, special training, or expertise a Threat Actor must have to perform the attack.",
        default=None,
    )
    resource_level: Optional[AttackResourceLevel] = Field(
        description="The organizational level at which this Threat Actor typically works.",
        default=None,
    )
    primary_motivation: Optional[AttackMotivation] = Field(
        description="The primary reason, motivation, or purpose behind this Threat Actor.",
        default=None,
    )
    secondary_motivations: Optional[list[AttackMotivation]] = Field(
        description="The secondary reasons, motivations, or purposes behind this Threat Actor.",
        default=None,
    )
    personal_motivations: Optional[list[AttackMotivation]] = Field(
        description="The personal reasons, motivations, or purposes of the Threat Actor regardless of organizational goals.",
        default=None,
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
            created_by_ref=self.author.id if self.author else None,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
        )


MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    import doctest

    doctest.testmod()
