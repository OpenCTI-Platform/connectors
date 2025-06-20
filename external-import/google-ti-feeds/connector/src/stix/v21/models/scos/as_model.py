"""The module defines a model for an Autonomous System (AS) in STIX 2.1 format."""

from typing import Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import (  # type: ignore[import-untyped]  # Missing library stubs
    AutonomousSystem,
    _STIXBase21,
)


class AutonomousSystemModel(BaseSCOModel):
    """Model representing an Autonomous System in STIX 2.1 format."""

    number: int = Field(
        ...,
        description="The assigned Autonomous System Number (ASN). Typically assigned by a Regional Internet Registry (RIR).",
    )
    name: Optional[str] = Field(
        default=None, description="The name of the AS, if known."
    )
    rir: Optional[str] = Field(
        default=None,
        description="Name of the RIR that assigned the ASN (e.g., ARIN, RIPE, APNIC).",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return AutonomousSystem(**self.model_dump(exclude_none=True))
