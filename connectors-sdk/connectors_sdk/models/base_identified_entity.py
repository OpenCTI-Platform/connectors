"""BaseIdentifiedEntity."""

from __future__ import annotations

from abc import ABC

from connectors_sdk.models._base_identified_entity import _BaseIdentifiedEntity
from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.external_reference import ExternalReference
from connectors_sdk.models.tlp_marking import TLPMarking
from pydantic import (
    Field,
    PrivateAttr,
)


class BaseIdentifiedEntity(_BaseIdentifiedEntity, ABC):
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
