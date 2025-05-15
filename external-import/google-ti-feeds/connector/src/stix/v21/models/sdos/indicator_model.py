"""The module contains the IndicatorModel class, which represents a STIX 2.1 Indicator object."""

from datetime import datetime
from typing import List, Literal, Optional

from connector.src.stix.v21.models.cdts.kill_chain_phase_model import (
    KillChainPhaseModel,
)
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import (
    IndicatorTypeOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Indicator, _STIXBase21  # type: ignore


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

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Indicator(**self.model_dump(exclude_none=True))


def test_indicator_model() -> None:
    """Test function to demonstrate the usage of IndicatorModel."""
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    # === Minimal Indicator ===
    minimal = IndicatorModel(
        type="indicator",
        spec_version="2.1",
        id=f"indicator--{uuid4()}",
        created=datetime.now(UTC),
        modified=datetime.now(UTC),
        indicator_types=[IndicatorTypeOV.MALICIOUS_ACTIVITY],
        pattern="[domain-name:value = 'malicious.example.com']",
        pattern_type="stix",
        valid_from=datetime.now(UTC),
    )

    print("=== MINIMAL INDICATOR ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Indicator ===
    full = IndicatorModel(
        type="indicator",
        spec_version="2.1",
        id=f"indicator--{uuid4()}",
        created=datetime.now(UTC),
        modified=datetime.now(UTC),
        name="Malicious C2 Beacon",
        description="Detects HTTP traffic patterns characteristic of C2 callbacks.",
        indicator_types=[
            IndicatorTypeOV.ANOMALOUS_ACTIVITY,
            IndicatorTypeOV.COMPROMISED,
        ],
        pattern="[url:value = 'http://c2.ghostops.org']",
        pattern_type="stix",
        pattern_version="2.1",
        valid_from=datetime.now(UTC),
        valid_until=datetime.now(UTC) + timedelta(days=60),
        kill_chain_phases=[
            KillChainPhaseModel(
                kill_chain_name="mitre-attack",
                phase_name="command-and-control",
            )
        ],
        labels=["network", "c2", "http"],
        confidence=80,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["pattern", "description"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "threat_score": 9.2,
            }
        },
    )

    print("\n=== FULL INDICATOR ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_indicator_model()
