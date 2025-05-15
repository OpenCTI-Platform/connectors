"""The module defines the OpinionModel class, which represents a STIX 2.1 Opinion object."""

from typing import List, Optional

from connector.src.stix.v21.models.ovs.opinion_ov_enums import OpinionOV
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Opinion, _STIXBase21  # type: ignore


class OpinionModel(BaseSDOModel):
    """Model representing an Opinion in STIX 2.1 format."""

    explanation: Optional[str] = Field(
        default=None,
        description="Explanation for the Opinion, including reasoning and any supporting evidence.",
    )
    authors: Optional[List[str]] = Field(
        default=None,
        description="List of authors (e.g., analysts) who created this Opinion.",
    )
    opinion: OpinionOV = Field(
        ...,
        description="The producer’s opinion about the object(s). MUST be a value from the opinion-enum.",
    )
    object_refs: List[str] = Field(
        ...,
        description="STIX Object identifiers that this Opinion applies to.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Opinion(**self.model_dump(exclude_none=True))


def test_opinion_model() -> None:
    """Test function to demonstrate the usage of OpinionModel."""
    from datetime import UTC, datetime
    from uuid import uuid4

    now = datetime.now(UTC)

    # === Minimal Opinion ===
    minimal = OpinionModel(
        type="opinion",
        spec_version="2.1",
        id=f"opinion--{uuid4()}",
        created=now,
        modified=now,
        opinion=OpinionOV.STRONGLY_DISAGREE,
        object_refs=[f"indicator--{uuid4()}"],
    )

    print("=== MINIMAL OPINION ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Opinion ===
    full = OpinionModel(
        type="opinion",
        spec_version="2.1",
        id=f"opinion--{uuid4()}",
        created=now,
        modified=now,
        explanation="Multiple indicators associated with this malware appear recycled from older threat actor kits. However, obfuscation techniques have improved.",
        authors=["Rei Hoshino", "Unit 9 SIGINT Cell"],
        opinion=OpinionOV.DISAGREE,
        object_refs=[f"malware--{uuid4()}", f"indicator--{uuid4()}"],
        labels=["attribution", "trust-analysis", "analyst-opinion"],
        confidence=70,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["explanation"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "review_status": "peer-reviewed",
            }
        },
    )

    print("\n=== FULL OPINION ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_opinion_model()
