"""The module defines the CourseOfActionModel class, which represents a course of action in STIX 2.1 format."""

from typing import List, Optional

from connector.src.stix.v21.models.cdts.external_reference_model import (
    ExternalReferenceModel,
)
from connector.src.stix.v21.models.ovs.course_of_action_type_ov_enums import (
    CourseOfActionTypeOV,
)
from connector.src.stix.v21.models.sdos.sdo_common_model import BaseSDOModel
from pydantic import Base64Bytes, Field, model_validator
from stix2.v21 import CourseOfAction, _STIXBase21  # type: ignore


class CourseOfActionModel(BaseSDOModel):
    """Model representing a Course of Action in STIX 2.1 format."""

    name: str = Field(
        ..., description="A name used to identify the Course of Action."
    )
    description: Optional[str] = Field(
        default=None,
        description="Context for the Course of Action, possibly including intent and characteristics. May contain prose.",
    )
    action_type: Optional[CourseOfActionTypeOV] = Field(
        default=None,
        description="Open vocabulary describing the action type (e.g., textual:text/plain). Should use course-of-action-type-ov.",
    )
    os_execution_envs: Optional[List[str]] = Field(
        default=None,
        description="Recommended OS environments for execution. Preferably CPE v2.3 from NVD. Can include custom values.",
    )
    action_bin: Optional[Base64Bytes] = Field(
        default=None,
        description="Base64-encoded binary representing the Course of Action. MUST NOT be set with action_reference.",
    )
    action_reference: Optional[ExternalReferenceModel] = Field(
        default=None,
        description="External reference to an action. MUST NOT be set if action_bin is present.",
    )

    @model_validator(mode="after")
    def validate_action_exclusivity(self, model):  # type: ignore
        """Ensure that only one of action_bin or action_reference is set."""
        if model.action_bin and model.action_reference:
            raise ValueError(
                "Only one of 'action_bin' or 'action_reference' may be set, not both."
            )
        return model

    def to_stix2_object(self) -> _STIXBase21:
        """Convert the model to a STIX 2.1 object."""
        return CourseOfAction(
            allow_custom=True, **self.model_dump(exclude_none=True)
        )  # allow_custom=True because stix2 doesn't support action_type, os_execution_envs, action_bin, action_reference.


def test_course_of_action_model() -> None:
    """Test function to demonstrate the usage of CourseOfActionModel."""
    from datetime import datetime
    from uuid import uuid4

    from connector.src.stix.v21.models.cdts.external_reference_model import (
        ExternalReferenceModel,
    )

    # === Minimal Course of Action ===
    minimal = CourseOfActionModel(
        type="course-of-action",
        spec_version="2.1",
        id=f"course-of-action--{uuid4()}",
        created=datetime.now(),
        modified=datetime.now(),
        name="Network Firewall Deployment",
    )

    print("=== MINIMAL COURSE OF ACTION ===")  # noqa: T201
    print(minimal.to_stix2_object().serialize(pretty=True))  # noqa: T201

    # === Full Course of Action ===
    # Simulated binary content
    encoded_bin = b"#!/bin/bash\necho 'defense'"

    full = CourseOfActionModel(
        type="course-of-action",
        spec_version="2.1",
        id=f"course-of-action--{uuid4()}",
        created=datetime.now(),
        modified=datetime.now(),
        name="Automated Threat Containment Script",
        description="A defensive response script to isolate infected endpoints.",
        action_type=CourseOfActionTypeOV.TEXTUAL_HTML,
        os_execution_envs=[
            "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
            "custom-os-xyz",
        ],
        action_bin=encoded_bin,
        labels=["containment", "automated-response"],
        confidence=90,
        lang="en",
        revoked=False,
        created_by_ref=f"identity--{uuid4()}",
        external_references=[
            ExternalReferenceModel(
                source_name="vendor-docs",
                url="https://example.com/response-playbook.pdf",
                description="Playbook used as a source for this automated action",
            )
        ],
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
                "integrity_checked": True,
            }
        },
    )

    print("\n=== FULL COURSE OF ACTION ===")  # noqa: T201
    print(full.to_stix2_object().serialize(pretty=True))  # noqa: T201


if __name__ == "__main__":
    test_course_of_action_model()
