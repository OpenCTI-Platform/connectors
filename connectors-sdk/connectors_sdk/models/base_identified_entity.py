"""BaseIdentifiedEntity."""

from __future__ import annotations

from abc import ABC
from typing import Any

from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.base_identified_object import BaseIdentifiedObject
from connectors_sdk.models.external_reference import ExternalReference
from connectors_sdk.models.tlp_marking import TLPMarking
from pydantic import Field, PrivateAttr


class BaseIdentifiedEntity(BaseIdentifiedObject, ABC):
    """Base class that can be identified thanks to a stix-like id."""

    _stix2_id: str | None = PrivateAttr(default=None)

    author: BaseAuthorEntity | None = Field(
        default=None,
        description="The Author reporting this Observable.",
    )

    markings: list[TLPMarking] | None = Field(
        default=None,
        description="References for object marking.",
    )

    external_references: list[ExternalReference] | None = Field(
        default=None,
        description="External references of the observable.",
    )

    def _common_stix2_properties(self) -> dict[str, Any]:
        """Return the common STIX2 properties set."""
        return dict(  # noqa: C408 # No literal dict for maintainability
            created_by_ref=(self.author.id if self.author else None),
            object_marking_refs=(
                [marking.id for marking in self.markings]
                if self.markings is not None
                else None
            ),
            external_references=(
                [
                    external_ref.to_stix2_object()
                    for external_ref in self.external_references
                ]
                if self.external_references is not None
                else None
            ),
        )
