"""The module contains the AttackPatternModel class, which represents an attack pattern in STIX 2.1 format."""

from typing import Any, Dict, List, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    AttackPattern,
    _STIXBase21,
)


class AttackPatternModel(BaseSDOModel):
    """Model representing an Attack Pattern in STIX 2.1 format."""

    name: str = Field(..., description="A name used to identify the Attack Pattern.")
    description: Optional[str] = Field(
        default=None,
        description="A description that provides more details and context about the Attack Pattern, potentially including its purpose and its key characteristics.",
    )
    aliases: Optional[List[str]] = Field(
        default=None,
        description="Alternative names used to identify this Attack Pattern.",
    )
    kill_chain_phases: Optional[List[KillChainPhaseModel]] = Field(
        default=None,
        description="The list of Kill Chain Phases for which this Attack Pattern is used.",
    )

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = AttackPatternModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "name" in data:
            x_mitre_id = data.get("custom_properties", {}).get("x_mitre_id", None)
            data["id"] = pycti.AttackPattern.generate_id(
                name=data["name"], x_mitre_id=x_mitre_id
            )
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = AttackPatternModel._generate_id(data=data)
        data.pop("id")

        return AttackPattern(id=pycti_id, **data)
