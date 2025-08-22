"""Offer OpenCTI entities."""

from typing import Optional

from connectors_sdk.models.octi._common import MODEL_REGISTRY, BaseIdentifiedEntity
from connectors_sdk.models.octi.enums import IndustrySector, Reliability
from pycti import Identity as PyctiIdentity
from pydantic import Field
from stix2.v21 import Identity as Stix2Identity


@MODEL_REGISTRY.register
class Organization(BaseIdentifiedEntity):
    """Defin an OCTI organization.

    Examples:
        >>> org = Organization(name="Example Corp")
        >>> entity = org.to_stix2_object()
    """

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
    organization_type: Optional[str] = Field(
        None,
        description="OpenCTI Type of the organization. By default, OpenCTI handles: "
        "'vendor', 'partner', 'constituent', 'csirt', 'other'."
        "See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts",
    )
    reliability: Optional[str] = Field(
        None,
        description="OpenCTI Reliability of the organization. By default, OpenCTI handles: "
        "'A - Completely reliable', "
        "'B - Usually reliable', "
        "'C - Fairly reliable', "
        "'D - Not usually reliable', "
        "'E - Unreliable', "
        "'F - Reliability cannot be judged'. "
        "See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts",
    )
    aliases: Optional[list[str]] = Field(
        None,
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
            id=PyctiIdentity.generate_id(identity_class=identity_class, name=self.name),
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
            granular_markings=None,
            extensions=None,
        )


@MODEL_REGISTRY.register
class Sector(BaseIdentifiedEntity):
    """Represents a Sector on OpenCTI."""

    name: str = Field(
        description="Name of the sector.",
        min_length=1,
    )
    description: Optional[str] = Field(
        description="Description of the sector.",
        default=None,
    )
    sectors: Optional[list[IndustrySector]] = Field(
        description="The list of industry sectors that this Identity belongs to.",
        default=None,
    )
    reliability: Optional[Reliability] = Field(
        description="OpenCTI Reliability of the sector. By default, OpenCTI handles: "
        "'A - Completely reliable', "
        "'B - Usually reliable', "
        "'C - Fairly reliable', "
        "'D - Not usually reliable', "
        "'E - Unreliable', "
        "'F - Reliability cannot be judged'. "
        "See https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/src/modules/vocabulary/vocabulary-utils.ts",
        default=None,
    )
    aliases: Optional[list[str]] = Field(
        description="Aliases of the sector.",
        default=None,
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
