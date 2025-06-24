"""The module contains the IndicatorModel class, which represents a STIX 2.1 Indicator object."""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

import pycti  # type: ignore  # Missing library stubs
from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field, model_validator
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    Indicator,
    _STIXBase21,
)


class IndicatorModel(BaseSDOModel):
    """Model representing an Indicator in STIX 2.1 format."""

    name: Optional[str] = Field(
        default=None,
        description="A name used to identify the Indicator. Helps analysts and tools understand its purpose.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Details and context about the Indicator's intent, behavior, and usage.",
    )
    indicator_types: List[IndicatorTypeOV] = Field(
        ...,
        description="Open vocabulary categorizing the type of Indicator. SHOULD come from the indicator-type-ov vocabulary.",
    )
    pattern: str = Field(
        ...,
        description="The detection pattern expressed using the STIX Pattern specification (section 9).",
    )
    pattern_type: Optional[Literal["stix", "snort", "yara"]] = Field(
        ...,
        description="The type of pattern used (e.g., stix, snort, yara). Open vocabulary.",
    )
    pattern_version: Optional[str] = Field(
        default=None,
        description="Version of the pattern used. If no spec version exists, use the build or code version.",
    )
    valid_from: datetime = Field(
        ...,
        description="Timestamp when the Indicator becomes valid for detecting behavior.",
    )
    valid_until: Optional[datetime] = Field(
        default=None,
        description="Timestamp when this Indicator is no longer considered valid. MUST be > valid_from if set.",
    )
    kill_chain_phases: Optional[List[KillChainPhaseModel]] = Field(
        default=None,
        description="Kill chain phases to which this Indicator corresponds.",
    )

    @model_validator(mode="before")
    @classmethod
    def generate_id(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate ID regardless of whether one is provided."""
        data["id"] = IndicatorModel._generate_id(data=data)
        return data

    @classmethod
    def _generate_id(cls, data: Dict[str, Any]) -> Any:
        """Generate ID regardless of whether one is provided."""
        if isinstance(data, dict) and "pattern" in data:
            pattern = data.get("pattern", None)
            data["id"] = pycti.Indicator.generate_id(pattern=pattern)
        return data["id"]

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        data = self.model_dump(exclude={"id"}, exclude_none=True)
        pycti_id = IndicatorModel._generate_id(data=data)
        data.pop("id")

        return Indicator(id=pycti_id, **data)
