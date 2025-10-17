"""BaseIdentifiedEntity."""

from __future__ import annotations

from typing import TYPE_CHECKING

from connectors_sdk.models._author import Author
from connectors_sdk.models._base_identified_entity import _BaseIdentifiedEntity
from connectors_sdk.models._model_registry import MODEL_REGISTRY
from pydantic import (
    Field,
    PrivateAttr,
)

if TYPE_CHECKING:
    from connectors_sdk.models.external_reference import ExternalReference
    from connectors_sdk.models.octi._common import TLPMarking


@MODEL_REGISTRY.register
class BaseIdentifiedEntity(_BaseIdentifiedEntity):
    """Base class that can be identified thanks to a stix-like id."""

    _stix2_id: str | None = PrivateAttr(default=None)

    author: Author | None = Field(
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
