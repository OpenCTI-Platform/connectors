"""Define OpenCTI entities."""

from abc import abstractmethod
from datetime import datetime
from typing import Any, Optional

import dragos.domain.models.octi.enums as octi_enums
import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from dragos.domain.models.octi.common import (
    Author,
    BaseEntity,
    ExternalReference,
    KillChainPhase,
    TLPMarking,
)
from dragos.domain.models.octi.types import (
    AttackMotivation,
    AttackResourceLevel,
    CvssSeverity,
    ImplementationLanguage,
    IndicatorType,
    IndustrySector,
    LocationType,
    MalwareCapability,
    MalwareType,
    ObservableType,
    OrganizationType,
    PatternType,
    Platform,
    ProcessorArchitecture,
    Region,
    Reliability,
    ReportType,
)
from pydantic import AwareDatetime, Field, PrivateAttr


class DomainObject(BaseEntity):
    """Base class for OpenCTI Domain Objects."""

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
            created_by_ref=self.author.id if self.author else None,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties=dict(  # noqa: C408 # No literal dict for maintainability
                x_opencti_score=self.score,
                x_mitre_platforms=self.platforms,
                x_opencti_main_observable_type=self.observable_type,
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
            extensions=None,
        )


class IntrusionSet(DomainObject):
    """Represent an intrusion set."""

    name: str = Field(
        ...,
        description="A name used to identify this Intrusion Set.",
        min_length=1,
    )
    description: Optional[str] = Field(
        None,
        description="A description that provides more details and context about the Intrusion Set.",
    )
    aliases: Optional[list[str]] = Field(
        None,
        description="Alternative names used to identify this Intrusion Set.",
    )
    first_seen: Optional[AwareDatetime] = Field(
        None,
        description="The time that this Intrusion Set was first seen.",
    )
    last_seen: Optional[AwareDatetime] = Field(
        None,
        description="The time that this Intrusion Set was last seen.",
    )
    goals: Optional[list[str]] = Field(
        None,
        description="The high-level goals of this Intrusion Set, namely, what are they trying to do.",
    )
    resource_level: Optional[AttackResourceLevel] = Field(
        None,
        description="The organizational level at which this Intrusion Set typically works.",
    )
    primary_motivation: Optional[AttackMotivation] = Field(
        None,
        description="The primary reason, motivation, or purpose behind this Intrusion Set.",
    )
    secondary_motivations: Optional[list[AttackMotivation]] = Field(
        None,
        description="The secondary reasons, motivations, or purposes behind this Intrusion Set.",
    )

    def to_stix2_object(self) -> stix2.v21.IntrusionSet:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(name=self.name),
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
            # unused
            created=None,
            modified=None,
            labels=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
        )


class _Location(DomainObject):
    """Represents a location entity."""

    _location_type: LocationType = PrivateAttr(...)

    name: Optional[str] = Field(
        None,
        description="A name used to identify the Location.",
    )
    description: Optional[str] = Field(
        None,
        description="A textual description of the Location.",
    )
    latitude: Optional[float] = Field(
        None,
        description="The latitude of the Location in decimal degrees.",
    )
    longitude: Optional[float] = Field(
        None,
        description="The longitude of the Location in decimal degrees.",
    )
    precision: Optional[float] = Field(
        None,
        description="Defines the precision of the coordinates specified by the latitude and longitude properties.",
    )
    region: Optional[Region] = Field(
        None,
        description="The region that this Location describes.",
    )
    country: Optional[str] = Field(
        None,
        description="The country that this Location describes.",
    )
    administrative_area: Optional[str] = Field(
        None,
        description="The state, province, or other sub-national administrative area that this Location describes.",
    )
    city: Optional[str] = Field(
        None,
        description="The city that this Location describes.",
    )
    street_address: Optional[str] = Field(
        None,
        description="The street address that this Location describes.",
    )
    postal_code: Optional[str] = Field(
        None,
        description="The postal code for this Location.",
    )

    def to_stix2_object(self) -> stix2.Location:
        return stix2.Location(
            id=pycti.Location.generate_id(
                name=self.name,
                x_opencti_location_type=self._location_type,
                latitude=self.latitude,
                longitude=self.longitude,
            ),
            name=self.name,
            description=self.description,
            latitude=self.latitude,
            longitude=self.longitude,
            precision=self.precision,
            region=self.region,
            country=self.country,
            administrative_area=self.administrative_area,
            city=self.city,
            street_address=self.street_address,
            postal_code=self.postal_code,
            custom_properties=dict(
                x_opencti_location_type=self._location_type,
            ),
            created=None,
            modified=None,
            revoked=None,
            labels=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
        )


class LocationAdministrativeArea(_Location):
    """Represent an administrative area entity."""

    _location_type = octi_enums.LocationType.ADMINISTRATIVE_AREA.value


class LocationCity(_Location):
    """Represent a city entity."""

    _location_type = octi_enums.LocationType.CITY.value


class LocationCountry(_Location):
    """Represent a country entity."""

    _location_type = octi_enums.LocationType.COUNTRY.value


class LocationPosition(_Location):
    """Represent a position entity."""

    _location_type = octi_enums.LocationType.POSITION.value


class LocationRegion(_Location):
    """Represent a region entity."""

    _location_type = octi_enums.LocationType.REGION.value


class Malware(DomainObject):
    """Represent a malware entity."""

    name: str = Field(
        ...,
        description="Name of the malware.",
        min_length=1,
    )
    is_family: bool = Field(
        ...,
        description="Is the malware a family?",
    )
    description: Optional[str] = Field(
        None,
        description="Description of the malware.",
    )
    aliases: Optional[list[str]] = Field(
        None,
        description="Alternative names used to identify this malware or malware family.",
    )
    types: Optional[list[MalwareType]] = Field(
        None,
        description="Types of the malware.",
    )
    first_seen: Optional[AwareDatetime] = Field(
        None,
        description="The time that this Malware was first seen.",
    )
    last_seen: Optional[AwareDatetime] = Field(
        None,
        description="The time that this Malware was last seen.",
    )
    architecture_execution_envs: Optional[list[ProcessorArchitecture]] = Field(
        None,
        description="Architecture execution environment of the malware.",
    )
    implementation_languages: Optional[list[ImplementationLanguage]] = Field(
        None,
        description="Implementation languages of the malware.",
    )
    kill_chain_phases: Optional[list[KillChainPhase]] = Field(
        None,
        description="Kill chain phases of the malware.",
    )
    capabilities: Optional[list[MalwareCapability]] = Field(
        None,
        description="Any of the capabilities identified for the malware instance or family.",
    )

    def to_stix2_object(self) -> stix2.v21.Malware:
        """Make stix object."""
        if self._stix2_representation is not None:
            return self._stix2_representation

        return stix2.Malware(
            id=pycti.Malware.generate_id(name=self.name),
            name=self.name,
            is_family=self.is_family,
            description=self.description,
            aliases=self.aliases,
            malware_types=self.types,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            architecture_execution_envs=self.architecture_execution_envs,
            implementation_languages=self.implementation_languages,
            kill_chain_phases=[
                kill_chain_phase.to_stix2_object()
                for kill_chain_phase in self.kill_chain_phases or []
            ],
            capabilities=self.capabilities,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            created_by_ref=self.author.id if self.author else None,
            object_marking_refs=[marking.id for marking in self.markings or []],
            # unused
            created=None,
            modified=None,
            operating_system_refs=None,  # not implemented on OpenCTI
            sample_refs=None,  # not implemented on OpenCTI
            revoked=None,
            labels=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
        )


class Organization(DomainObject):
    """Represent an organization."""

    # OpenCTI maps STIX Identity SDO to OCTI Organization entity based on `identity_class`.
    # To create an Organization entity on OpenCTI, `identity_class` MUST be 'organization'.
    _identity_class = PrivateAttr(octi_enums.IdentityClass.ORGANIZATION.value)

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

        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class=self._identity_class, name=self.name
            ),
            identity_class=self._identity_class,
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
            granular_markings=None,
            extensions=None,
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
    description: Optional[str] = Field(
        None,
        description="Description of the report.",
    )
    report_types: Optional[list[ReportType]] = Field(
        None,
        description="Report types.",
    )
    reliability: Optional[Reliability] = Field(
        None,
        description="Reliability of the report.",
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


class Sector(DomainObject):
    """Represents a sector entity."""

    # OpenCTI maps STIX Identity SDO to OCTI Sector entity based on `identity_class`.
    # To create a Sector entity on OpenCTI, `identity_class` MUST be 'class'.
    _identity_class = PrivateAttr(octi_enums.IdentityClass.CLASS.value)

    name: str = Field(
        ...,
        description="Name of the sector.",
        min_length=1,
    )
    description: Optional[str] = Field(
        None,
        description="Description of the sector.",
    )
    sectors: Optional[list[IndustrySector]] = Field(
        None,
        description="The list of industry sectors that this Identity belongs to.",
    )
    reliability: Optional[Reliability] = Field(
        None,
        description="OpenCTI Reliability of the sector.",
    )
    aliases: Optional[list[str]] = Field(
        None,
        description="Aliases of the sector.",
    )

    def to_stix2_object(self) -> stix2.Identity:
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                identity_class=self._identity_class, name=self.name
            ),
            identity_class=self._identity_class,
            name=self.name,
            description=self.description,
            sectors=self.sectors,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            created_by_ref=self.author.id if self.author else None,
            custom_properties=dict(  # noqa: C408  # No literal dict for maintainability
                x_opencti_reliability=self.reliability,
                x_opencti_aliases=self.aliases,
            ),
            # unused
            created=None,
            modified=None,
            roles=None,
            contact_information=None,
            revoked=None,
            labels=None,
            confidence=None,
            lang=None,
            granular_markings=None,
            extensions=None,
        )


class Vulnerability(DomainObject):
    """Represents a vulnerability entity."""

    name: str = Field(
        ...,
        description="Name of the vulnerability.",
        min_length=1,
    )
    description: Optional[str] = Field(
        None,
        description="Description of the vulnerability.",
    )
    aliases: Optional[list[str]] = Field(
        None,
        description="Vulnerability aliases",
    )
    cvss_score: Optional[float] = Field(
        None,
        description="The CVSS v3 base score.",
        ge=0,
        le=10,
    )
    cvss_severity: Optional[CvssSeverity] = Field(
        None,
        description="CVSS3 Severity",
    )
    cvss_attack_vector: Optional[str] = Field(
        None,
        description="CVSS3 Attack vector (AV)",
    )
    cvss_integrity_impact: Optional[str] = Field(
        None,
        description="CVSS3 Integrity impact (I)",
    )
    cvss_availability_impact: Optional[str] = Field(
        None,
        description="CVSS3 Availability impact (A)",
    )
    cvss_confidentiality_impact: Optional[str] = Field(
        None,
        description="CVSS3 Confidentiality impact (C)",
    )
    is_cisa_kev: Optional[bool] = Field(
        None,
        description="Whether vulnerability is a CISA Known Exploited Vulnerability.",
    )
    epss_score: Optional[float] = Field(
        None,
        description="EPSS score.",
        ge=0,
        le=1,
    )
    epss_percentile: Optional[float] = Field(
        None,
        description="EPSS percentile.",
        ge=0,
        le=1,
    )

    def to_stix2_object(self) -> stix2.Vulnerability:
        """Make stix object."""
        return stix2.Vulnerability(
            id=pycti.Vulnerability.generate_id(self.name),
            name=self.name,
            description=self.description,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            created_by_ref=self.author.id if self.author else None,
            object_marking_refs=[marking.id for marking in self.markings or []],
            custom_properties=dict(
                x_opencti_aliases=self.aliases,
                x_opencti_cvss_base_score=self.cvss_score,
                x_opencti_cvss_base_severity=self.cvss_severity,
                x_opencti_cvss_attack_vector=self.cvss_attack_vector,
                x_opencti_cvss_integrity_impact=self.cvss_integrity_impact,
                x_opencti_cvss_availability_impact=self.cvss_availability_impact,
                x_opencti_cvss_confidentiality_impact=self.cvss_confidentiality_impact,
                x_opencti_cisa_kev=self.is_cisa_kev,
                x_opencti_epss_score=self.epss_score,
                x_opencti_epss_percentile=self.epss_percentile,
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
