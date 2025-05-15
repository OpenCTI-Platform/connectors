"""The module defines a model for an Autonomous System (AS) in STIX 2.1 format."""

from typing import Optional

from connector.src.stix.v21.models.scos.sco_common_model import BaseSCOModel
from pydantic import Field
from stix2.v21 import AutonomousSystem, _STIXBase21  # type: ignore


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


def test_autonomous_system_model() -> None:
    """Test function to demonstrate the usage of AutonomousSystemModel."""
    from uuid import uuid4

    # === Minimal Autonomous System ===
    minimal = AutonomousSystemModel(
        type="autonomous-system",
        spec_version="2.1",
        id=f"autonomous-system--{uuid4()}",
        number=64512,  # Reserved private ASN range
    )

    print("=== MINIMAL AUTONOMOUS SYSTEM ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Autonomous System ===
    full = AutonomousSystemModel(
        type="autonomous-system",
        spec_version="2.1",
        id=f"autonomous-system--{uuid4()}",
        number=13335,  # Cloudflare's ASN
        name="CLOUDFLARENET",
        rir="ARIN",
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["name", "rir"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "property-extension",
                "prefix": "asn-lookup",
            }
        },
    )

    print("\n=== FULL AUTONOMOUS SYSTEM ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_autonomous_system_model()
