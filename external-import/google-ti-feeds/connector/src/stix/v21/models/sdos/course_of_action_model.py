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

    name: str = Field(..., description="A name used to identify the Course of Action.")
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
        return CourseOfAction(allow_custom=True, **self.model_dump(exclude_none=True))
