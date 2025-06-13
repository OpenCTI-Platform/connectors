"""The module contains the IdentityModel class, which represents a STIX 2.1 Identity object."""

from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.ovs.identity_class_ov_enums import IdentityClassOV
from connector.src.stix.v21.models.ovs.industry_sector_ov_enums import IndustrySectorOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Identity,
    _STIXBase21,
)


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

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = IdentityModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            name = data.get("name", None)
            identity_class = data.get("identity_class", None)
            data["id"] = pycti.Identity.generate_id(
                name=name, identity_class=identity_class
            )
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = IdentityModel._generate_id(data=data)
        data.pop("id")

        return Identity(id=pycti_id, **data)
