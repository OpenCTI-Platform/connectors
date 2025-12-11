"""Define the OpenCTI Relationships."""

from typing import Any, Literal, Optional

import pycti  # type: ignore[import-untyped]  # pycti does not provide stubs
import stix2  # type: ignore[import-untyped] # stix2 does not provide stubs
from dragos.domain.models.octi.common import (
    Author,
    BaseEntity,
    ExternalReference,
    TLPMarking,
)
from dragos.domain.models.octi.domain import Indicator
from dragos.domain.models.octi.observables import Observable
from pydantic import AwareDatetime, Field, PrivateAttr


class Relationship(BaseEntity):
    """Base class for OpenCTI relationships."""

    _relationship_type: str = PrivateAttr("")

    source: BaseEntity = Field(
        ...,
        description="The source entity of the relationship.",
    )
    target: BaseEntity = Field(
        ...,
        description="The target entity of the relationship.",
    )
    description: Optional[str] = Field(
        None,
        description="Description of the relationship.",
    )
    start_time: Optional[AwareDatetime] = Field(
        None,
        description="Start time of the relationship in ISO 8601 format.",
    )
    stop_time: Optional[AwareDatetime] = Field(
        None,
        description="End time of the relationship in ISO 8601 format.",
    )
    author: Optional[Author] = Field(
        None,
        description="Reference to the author that reported this relationship.",
    )
    markings: Optional[list[TLPMarking]] = Field(
        None,
        description="References for object marking",
    )
    external_references: Optional[list[ExternalReference]] = Field(
        None,
        description="External references",
    )

    def to_stix2_object(self) -> stix2.v21.Relationship:
        """Make stix object."""
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relationship_type=self._relationship_type,
                source_ref=self.source.id,
                target_ref=self.target.id,
                start_time=self.start_time,
                stop_time=self.stop_time,
            ),
            relationship_type=self._relationship_type,
            **self._common_stix2_args(),
        )

    def _common_stix2_args(self) -> dict[str, Any]:
        """Factorize custom params."""
        return dict(  # noqa: C408 # No literal dict for maintainability
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
            # unused
            created=None,
            modified=None,
        )


class IndicatorBasedOnObservable(Relationship):
    """Represent a relationship indicating that an indicator is based on an observable."""

    _relationship_type: Literal["based-on"] = "based-on"

    source: Indicator = Field(
        ...,
        description="Reference to the source entity of the relationship. Here an Indicator.",
    )
    target: Observable = Field(
        ...,
        description="Reference to the target entity of the relationship. Here an Observable.",
    )
