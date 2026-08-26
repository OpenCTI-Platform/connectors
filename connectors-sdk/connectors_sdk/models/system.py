"""System."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import (
    Reliability,
)
from pycti import Identity as PyctiIdentity
from pydantic import Field
from stix2.v21 import Identity as Stix2Identity


class System(BaseIdentifiedEntity):
    """Define an OCTI system.

    Systems represent software applications, platforms, frameworks or specific
    tools such as WordPress, VirtualBox, Firefox or Python.

    Examples:
        >>> system = System(name="WordPress")
        >>> entity = system.to_stix2_object()
    """

    name: str = Field(
        description="Name of the system.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the system.",
    )
    contact_information: str | None = Field(
        default=None,
        description="Contact information for the system.",
    )
    reliability: Reliability | None = Field(
        default=None,
        description="OpenCTI Reliability of the system.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Aliases of the system.",
    )

    def to_stix2_object(self) -> Stix2Identity:
        """Make stix object.

        Notes:
            - OpenCTI maps STIX Identity SDO to OCTI System entity based on `identity_class`.
            - To create a System entity on OpenCTI, `identity_class` MUST be 'system'.
        """
        identity_class = "system"

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
            x_opencti_reliability=self.reliability,
            x_opencti_aliases=self.aliases,
            **self._common_stix2_properties()
        )
