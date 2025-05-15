"""The module contains the GroupingModel class, which represents a STIX 2.1 Grouping object."""

from typing import List, Optional

from connector.src.stix.v21.models.ovs.grouping_context_ov_enums import (
    GroupingContextOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Field
from stix2.v21 import Grouping, _STIXBase21  # type: ignore


class GroupingModel(BaseSDOModel):
    """Model representing a Grouping in STIX 2.1 format."""

    name: Optional[str] = Field(
        default=None, description="A name used to identify the Grouping."
    )
    description: Optional[str] = Field(
        default=None,
        description="A description that provides more details and context about the Grouping, potentially including its purpose and key characteristics.",
    )
    context: GroupingContextOV = Field(
        ...,
        description="Short descriptor of the context shared by the content in this Grouping. SHOULD come from the grouping-context-ov vocabulary.",
    )
    object_refs: List[str] = Field(
        ...,
        description="List of STIX Object identifiers referred to by this Grouping.",
    )

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return Grouping(**self.model_dump(exclude_none=True))


def test_grouping_model() -> None:
    """Test function to demonstrate the usage of GroupingModel."""
    from datetime import datetime
    from uuid import uuid4

    # === Minimal Grouping ===
    minimal = GroupingModel(
        type="grouping",
        spec_version="2.1",
        id=f"grouping--{uuid4()}",
        created=datetime.now(),
        modified=datetime.now(),
        context=GroupingContextOV.SUSPICIOUS_ACTIVITY,
        object_refs=[f"indicator--{uuid4()}"],
    )

    print("=== MINIMAL GROUPING ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Grouping ===
    full = GroupingModel(
        type="grouping",
        spec_version="2.1",
        id=f"grouping--{uuid4()}",
        created=datetime.now(),
        modified=datetime.now(),
        name="Cluster of Suspicious Activity",
        description="Multiple STIX objects tied together from a related campaign and sighting.",
        context=GroupingContextOV.SUSPICIOUS_ACTIVITY,
        object_refs=[
            f"indicator--{uuid4()}",
            f"malware--{uuid4()}",
            f"threat-actor--{uuid4()}",
        ],
        created_by_ref=f"identity--{uuid4()}",
        revoked=False,
        labels=["campaign", "linked-threats"],
        confidence=70,
        lang="en",
        external_references=[],
        object_marking_refs=[f"marking-definition--{uuid4()}"],
        granular_markings=[
            {
                "selectors": ["description"],
                "marking_ref": f"marking-definition--{uuid4()}",
            }
        ],
        extensions={
            f"extension-definition--{uuid4()}": {
                "extension_type": "new-sdo",
                "classification": "internal",
            }
        },
    )

    print("\n=== FULL GROUPING ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_grouping_model()
