"""Offer OpenCTI entities."""

from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.octi.enums import (
    IndustrySector,
    OrganizationType,
    Reliability,
)
from pycti import Identity as PyctiIdentity
from pydantic import Field
from stix2.v21 import Identity as Stix2Identity


@MODEL_REGISTRY.register
class Individual(BaseIdentifiedEntity):
    """Define an OCTI organization.

    Examples:
        >>> individual = Individual(name="John Doe")
        >>> entity = individual.to_stix2_object()
    """

    name: str = Field(
        description="Name of the organization.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the organization.",
    )
    contact_information: str | None = Field(
        default=None,
        description="Contact information for the organization.",
    )
    reliability: Reliability | None = Field(
        default=None,
        description="OpenCTI Reliability of the organization.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Aliases of the organization.",
    )

    def to_stix2_object(self) -> Stix2Identity:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Identity SDO to OCTI Individual entity based on `identity_class`.
            - To create an Individual entity on OpenCTI, `identity_class` MUST be 'individual'.
        """
        identity_class = "individual"

        return Stix2Identity(
            id=PyctiIdentity.generate_id(
                identity_class=identity_class,
                name=self.name,
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
            allow_custom=True,
            x_opencti_reliability=self.reliability,
            x_opencti_aliases=self.aliases,
        )


@MODEL_REGISTRY.register
class Organization(BaseIdentifiedEntity):
    """Define an OCTI organization.

    Examples:
        >>> org = Organization(name="Example Corp")
        >>> entity = org.to_stix2_object()
    """

    name: str = Field(
        description="Name of the organization.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the organization.",
    )
    contact_information: str | None = Field(
        default=None,
        description="Contact information for the organization.",
    )
    organization_type: OrganizationType | None = Field(
        default=None,
        description="OpenCTI Type of the organization.",
    )
    reliability: Reliability | None = Field(
        default=None,
        description="OpenCTI Reliability of the organization.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Aliases of the organization.",
    )

    def to_stix2_object(self) -> Stix2Identity:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Identity SDO to OCTI Organization entity based on `identity_class`.
            - To create an Organization entity on OpenCTI, `identity_class` MUST be 'organization'.
        """
        identity_class = "organization"

        return Stix2Identity(
            id=PyctiIdentity.generate_id(
                identity_class=identity_class,
                name=self.name,
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
            allow_custom=True,
            x_opencti_organization_type=self.organization_type,
            x_opencti_reliability=self.reliability,
            x_opencti_aliases=self.aliases,
        )


@MODEL_REGISTRY.register
class Sector(BaseIdentifiedEntity):
    """Represents a Sector on OpenCTI."""

    name: str = Field(
        description="Name of the sector.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the sector.",
    )
    sectors: list[IndustrySector] | None = Field(
        default=None,
        description="The list of industry sectors that this Identity belongs to.",
    )
    reliability: Reliability | None = Field(
        default=None,
        description="OpenCTI Reliability of the sector.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Aliases of the sector.",
    )

    def to_stix2_object(self) -> Stix2Identity:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Identity SDO to OCTI Sector entity based on `identity_class`.
            - To create a Sector entity on OpenCTI, `identity_class` MUST be 'class'.
        """
        identity_class = "class"

        return Stix2Identity(
            id=PyctiIdentity.generate_id(identity_class=identity_class, name=self.name),
            identity_class=identity_class,
            name=self.name,
            description=self.description,
            sectors=self.sectors,
            external_references=[
                external_reference.to_stix2_object()
                for external_reference in self.external_references or []
            ],
            object_marking_refs=[marking.id for marking in self.markings or []],
            created_by_ref=self.author.id if self.author else None,
            allow_custom=True,
            x_opencti_reliability=self.reliability,
            x_opencti_aliases=self.aliases,
        )


# See https://docs.pydantic.dev/latest/errors/usage_errors/#class-not-fully-defined (consulted on 2025-06-10)
MODEL_REGISTRY.rebuild_all()

if __name__ == "__main__":  # pragma: no cover  # Do not run coverage on doctest
    import doctest

    doctest.testmod()
