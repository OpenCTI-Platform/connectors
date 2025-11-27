"""Relationship."""

from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import RelationshipType
from pycti import StixCoreRelationship as PyctiStixCoreRelationship
from pydantic import AwareDatetime, Field
from stix2.v21 import Relationship as Stix2Relationship


class Relationship(BaseIdentifiedEntity):
    """Base class for OpenCTI relationships."""

    type: RelationshipType = Field(
        description="Type of the relationship.",
    )
    source: BaseIdentifiedEntity = Field(
        description="The source entity of the relationship.",
    )
    target: BaseIdentifiedEntity = Field(
        description="The target entity of the relationship.",
    )
    description: str | None = Field(
        default=None,
        description="Description of the relationship.",
    )
    start_time: AwareDatetime | None = Field(
        default=None,
        description="Start time of the relationship in ISO 8601 format.",
    )
    stop_time: AwareDatetime | None = Field(
        default=None,
        description="End time of the relationship in ISO 8601 format.",
    )

    def to_stix2_object(self) -> Stix2Relationship:
        """Make stix object."""
        return Stix2Relationship(
            id=PyctiStixCoreRelationship.generate_id(
                relationship_type=self.type,
                source_ref=self.source.id,
                target_ref=self.target.id,
                start_time=self.start_time,
                stop_time=self.stop_time,
            ),
            relationship_type=self.type,
            source_ref=self.source.id,
            target_ref=self.target.id,
            description=self.description,
            start_time=self.start_time,
            stop_time=self.stop_time,
            **self._common_stix2_properties()
        )
