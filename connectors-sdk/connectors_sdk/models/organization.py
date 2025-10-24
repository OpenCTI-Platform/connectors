"""Organization."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import (
    OrganizationType,
    Reliability,
)
from pycti import Identity as PyctiIdentity
from pydantic import Field
from stix2.v21 import Identity as Stix2Identity


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
            allow_custom=True,
            x_opencti_organization_type=self.organization_type,
            x_opencti_reliability=self.reliability,
            x_opencti_aliases=self.aliases,
            **self._common_stix2_properties()
        )
