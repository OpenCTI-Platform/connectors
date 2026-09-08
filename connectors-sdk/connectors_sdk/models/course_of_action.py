"""CourseOfAction."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from pycti import CourseOfAction as PyctiCourseOfAction
from pydantic import Field
from stix2.v21 import CourseOfAction as Stix2CourseOfAction


class CourseOfAction(BaseIdentifiedEntity):
    """Represents a course of action (mitigation) entity on OpenCTI.

    See https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html#course-of-action-properties
    """

    name: str = Field(
        description="Name of the course of action.",
        min_length=1,
    )
    description: str | None = Field(
        default=None,
        description="Description of the course of action.",
    )
    aliases: list[str] | None = Field(
        default=None,
        description="Course of action aliases.",
    )
    mitre_id: str | None = Field(
        default=None,
        description="MITRE ATT&CK ID of the course of action.",
    )

    def to_stix2_object(self) -> Stix2CourseOfAction:
        """Make CourseOfAction STIX2.1 object."""
        return Stix2CourseOfAction(
            id=PyctiCourseOfAction.generate_id(
                name=self.name,
                x_mitre_id=self.mitre_id,
            ),
            name=self.name,
            description=self.description,
            allow_custom=True,
            x_opencti_aliases=self.aliases,
            x_mitre_id=self.mitre_id,
            **self._common_stix2_properties(),
        )
