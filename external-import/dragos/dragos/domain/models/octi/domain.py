"""Define OpenCTI entities."""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Literal, Optional

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from dragos.domain.models.octi.common import (
    Author,
    AttackMotivation,
    AttackResourceLevel,
    BaseEntity,
    ExternalReference,
    IndicatorType,
    KillChainPhase,
    ObservableType,
    OrganizationType,
    PatternType,
    Platform,
    Reliability,
    ReportType,
    ThreatActorRole,
    ThreatActorType,
    ThreatActorSophistication,
    TLPMarking,
)
from pydantic import AwareDatetime, Field


class DomainObject(BaseEntity):
    """Base class for STIX Domain Objects."""

    author: Optional[Author] = Field(
        None,
        description="Author of the report.",
    )
    markings: Optional[list[TLPMarking]] = Field(
        None,
        description="Markings of the report.",
    )
    external_references: Optional[list[ExternalReference]] = Field(
        None,
        description="External references of the report.",
    )

    @abstractmethod
    def to_stix2_object(self) -> Any:
        """Make stix object"""


class Indicator(DomainObject):
    """Represent an Indicator."""

    name: str = Field(
        ...,
        description="Name of the indicator.",
        min_length=1,
    )
    pattern: str = Field(
        ...,
        description="Pattern. See Stix2.1 for instance : https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_me3pzm77qfnf",
    )
    pattern_type: PatternType = Field(
        ...,
        description="Pattern type.",
    )
    observable_type: ObservableType = Field(
        ...,
        description="Observable type.",
    )
    description: Optional[str] = Field(
        None,
        description="Description of the indicator.",
    )
    indicator_types: Optional[list[IndicatorType]] = Field(
        None,
        description="Indicator types.",
    )
    platforms: Optional[list[Platform]] = Field(
        None,
        description="Platforms.",
    )
    valid_from: Optional[datetime] = Field(
        None,
        description="Valid from.",
    )
    valid_until: Optional[datetime] = Field(
        None,
        description="Valid until.",
    )
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(
        None,
        description="Kill chain phases.",
    )
    score: Optional[int] = Field(
        None,
        description="Score of the indicator.",
        ge=0,
        le=100,
    )

    def to_stix2_object(self) -> stix2.v21.Indicator:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.Indicator(
            id=pycti.Indicator.generate_id(pattern=self.pattern),
            name=self.name,
            description=self.description,
            indicator_types=self.indicator_types,
            pattern_type=self.pattern_type,
            pattern=self.pattern,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties=dict(  # noqa: C408 # No literal dict for maintainability
                x_opencti_score=self.score,
                x_mitre_platforms=self.platforms,
                x_opencti_main_observable_type=self.observable_type,
                x_opencti_created_by_ref=self.author.id if self.author else None,
                # unused
                x_opencti_detection=None,
            ),
            # unused
            created=None,
            modified=None,
            revoked=None,
            labels=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            pattern_version=None,
            extensions=None,
        )


class Organization(DomainObject):
    """Represent an organization."""

    name: str = Field(
        ...,
        description="Name of the organization.",
        min_length=1,
    )
    description: Optional[str] = Field(
        None,
        description="Description of the organization.",
    )
    contact_information: Optional[str] = Field(
        None,
        description="Contact information for the organization.",
    )
    organization_type: Optional[OrganizationType] = Field(
        None,
        description="OpenCTI Type of the organization.",
    )
    reliability: Optional[Reliability] = Field(
        None,
        description="OpenCTI Reliability of the organization.",
    )
    aliases: Optional[list[str]] = Field(
        None,
        description="Aliases of the organization.",
    )

    def to_stix2_object(self) -> stix2.v21.Identity:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        identity_class = "organization"
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class=identity_class, name=self.name
            ),
            identity_class=identity_class,
            name=self.name,
            description=self.description,
            contact_information=self.contact_information,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            created_by_ref=self.author.id if self.author else None,
            custom_properties=dict(  # noqa: C408  # No literal dict for maintainability
                x_opencti_organization_type=self.organization_type,
                x_opencti_reliability=self.reliability,
                x_opencti_aliases=self.aliases,
            ),
            # unused
            created=None,
            modified=None,
            roles=None,
            sectors=None,
            revoked=None,
            labels=None,
            confidence=None,
            lang=None,
        )


class OrganizationAuthor(Author, Organization):
    """Represent an organization author."""

    def to_stix2_object(self) -> stix2.v21.Identity:
        """Make stix object."""
        return Organization.to_stix2_object(self)


class Report(DomainObject):
    """Represent a report."""

    name: str = Field(
        ...,
        description="Name of the report.",
        min_length=1,
    )
    publication_date: AwareDatetime = Field(
        ...,
        description="Publication date of the report.",
    )
    objects: list[BaseEntity] = Field(
        ...,
        description="Objects of the report.",
        min_length=1,
    )
    report_types: Optional[list[ReportType]] = Field(
        None,
        description="Report types.",
    )
    reliability: Optional[Reliability] = Field(
        None,
        description="Reliability of the report.",
    )
    description: Optional[str] = Field(
        None,
        description="Description of the report.",
    )

    def to_stix2_object(self) -> stix2.v21.Report:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.Report(
            id=pycti.Report.generate_id(
                name=self.name, published=self.publication_date
            ),
            name=self.name,
            description=self.description,
            object_refs=[obj.id for obj in self.objects],
            report_types=self.report_types,
            published=self.publication_date,
            created_by_ref=self.author.id if self.author else None,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties=dict(  # noqa: C408  # No literal dict for maintainability
                x_opencti_reliability=self.reliability,
                # unused
                x_opencti_workflow_id=None,  # set by OpenCTI only, workflow ids are customizable
            ),
            # unused
            created=None,
            modified=None,
            revoked=None,
            confidence=None,
            labels=None,
            lang=None,
            granular_markings=None,
            extensions=None,
        )


class _ThreatActor(DomainObject):
    """Base class of ThreatActorGroup and ThreatActorIndividual classes."""

    name: str = Field(
        ...,
        description="A name used to identify this Threat Actor or Threat Actor group.",
        min_length=1,
    )
    description: Optional[str] = Field(
        None,
        description="A description that provides more details and context about the Threat Actor.",
    )
    threat_actor_types: Optional[list[ThreatActorType]] = Field(
        None,
        description="The type(s) of this threat actor.",
    )
    aliases: Optional[list[str]] = Field(
        None,
        description="A list of other names that this Threat Actor is believed to use.",
    )
    first_seen: Optional[AwareDatetime] = Field(
        None,
        description="The time that this Threat Actor was first seen.",
    )
    last_seen: Optional[AwareDatetime] = Field(
        None,
        description="The time that this Threat Actor was last seen.",
    )
    roles: Optional[list[ThreatActorRole]] = Field(
        None,
        description="A list of roles the Threat Actor plays.",
    )
    goals: Optional[list[str]] = Field(
        None,
        description="The high-level goals of this Threat Actor, namely, what are they trying to do.",
    )
    sophistication: Optional[ThreatActorSophistication] = Field(
        None,
        description="The skill, specific knowledge, special training, or expertise a Threat Actor must have to perform the attack.",
    )
    resource_level: Optional[AttackResourceLevel] = Field(
        None,
        description="The organizational level at which this Threat Actor typically works.",
    )
    primary_motivation: Optional[AttackMotivation] = Field(
        None,
        description="The primary reason, motivation, or purpose behind this Threat Actor.",
    )
    secondary_motivations: Optional[list[AttackMotivation]] = Field(
        None,
        description="The secondary reasons, motivations, or purposes behind this Threat Actor.",
    )
    personal_motivations: Optional[list[AttackMotivation]] = Field(
        None,
        description="The personal reasons, motivations, or purposes of the Threat Actor regardless of organizational goals.",
    )
    type: Optional[Literal["Threat-Actor-Individual", "Threat-Actor-Group"]] = Field(
        None,
        description="OpenCTI threat actor type.",
    )

    def to_stix2_object(self) -> stix2.v21.ThreatActor:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.ThreatActor(
            id=pycti.ThreatActor.generate_id(name=self.name, opencti_type=self.type),
            name=self.name,
            description=self.description,
            threat_actor_types=self.threat_actor_types,
            aliases=self.aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            roles=self.roles,
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
            custom_properties=dict(  # noqa: C408  # No literal dict for maintainability
                x_opencti_type=self.type,
            ),
            # unused
            created=None,
            modified=None,
            revoked=None,
            confidence=None,
            labels=None,
            lang=None,
            granular_markings=None,
            extensions=None,
        )


class ThreatActorGroup(_ThreatActor):
    """Represent a threat actor group."""

    type: Literal["Threat-Actor-Group"] = "Threat-Actor-Group"


class ThreatActorIndividual(_ThreatActor):
    """Represent a threat actor individual."""

    type: Literal["Threat-Actor-Individual"] = "Threat-Actor-Individual"
