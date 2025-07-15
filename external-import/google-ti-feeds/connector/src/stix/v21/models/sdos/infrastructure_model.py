"""The module defines the InfrastructureModel class, which represents a STIX 2.1 Infrastructure object."""

from datetime import datetime
from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.infrastructure_type_ov_enums import (
    InfrastructureTypeOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Infrastructure,
    _STIXBase21,
)


class InfrastructureModel(BaseSDOModel):
    """Model representing an Infrastructure in STIX 2.1 format."""

    name: str = Field(
        ...,
        description="A name or characterizing text used to identify the Infrastructure.",
    )
    description: Optional[str] = Field(
        default=None,
        description="More details and context about the Infrastructure—purpose, use, relationships, and key characteristics.",
    )
    infrastructure_types: List[InfrastructureTypeOV] = Field(
        ...,
        description="Open vocabulary describing the type(s) of Infrastructure. SHOULD come from the infrastructure-type-ov vocabulary.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Alternative names used to identify this Infrastructure.",
    )
    kill_chain_phases: Optional[List[KillChainPhaseModel]] = Field(
        default=None,
        description="Kill Chain Phases for which this Infrastructure is used.",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Timestamp when this Infrastructure was first observed performing malicious activity.",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Timestamp when this Infrastructure was last observed. MUST be >= first_seen if both are present.",
    )

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = InfrastructureModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            data["id"] = pycti.Infrastructure.generate_id(name=data["name"])
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = InfrastructureModel._generate_id(data=data)
        data.pop("id")

        return Infrastructure(id=pycti_id, **data)
