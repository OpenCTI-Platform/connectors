"""The module contains the IdentityModel class, which represents a STIX 2.1 Identity object."""

from typing import List, Optional

from connector.src.stix.v21.models.ovs.identity_class_ov_enums import (
    IdentityClassOV,
)
from connector.src.stix.v21.models.ovs.industry_sector_ov_enums import (
    IndustrySectorOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Identity, _STIXBase21  # type: ignore


class IdentityModel(BaseSDOModel):
    """Model representing an Identity in STIX 2.1 format."""

    name: str = Field(
        ...,
        description="The name of this Identity. SHOULD be the canonical name when referring to a specific entity.",
    )
    description: Optional[str] = Field(
        default=None,
        description="More details and context about the Identity, including its purpose and characteristics.",
    )
    roles: Optional[List[str]] = Field(
        default=None,
        description="The roles this Identity performs (e.g., CEO, Domain Admins, Doctors). No open vocabulary yet defined.",
    )
    identity_class: IdentityClassOV = Field(
        ...,
        description="The type of entity described by this Identity. SHOULD come from the identity-class-ov vocabulary.",
    )
    sectors: Optional[List[IndustrySectorOV]] = Field(
        default=None,
        description="Industry sectors this Identity belongs to. SHOULD come from the industry-sector-ov vocabulary.",
    )
    contact_information: Optional[str] = Field(
        default=None,
        description="Contact details for this Identity (email, phone, etc.). No defined format.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Identity(**self.model_dump(exclude_none=True))
