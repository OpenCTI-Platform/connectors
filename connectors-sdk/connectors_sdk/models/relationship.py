"""Relationship."""

from typing import Literal

from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from pycti import StixCoreRelationship as PyctiStixCoreRelationship
from pydantic import AwareDatetime, Field
from stix2.v21 import Relationship as Stix2Relationship


@MODEL_REGISTRY.register
class Relationship(BaseIdentifiedEntity):
    """Base class for OpenCTI relationships."""

    type: Literal[
        "related-to",
        "based-on",
        "derived-from",
        "indicates",
        "targets",
        "located-at",
        "has",
    ] = Field(description="Type of the relationship.")
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
            created_by_ref=self.author.id if self.author else None,
            object_marking_refs=[marking.id for marking in self.markings or []],
            external_references=[
                ref.to_stix2_object() for ref in self.external_references or []
            ],
        )
