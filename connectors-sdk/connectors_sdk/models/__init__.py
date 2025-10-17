"""Offer models."""

from connectors_sdk.models.octi import (
    AssociatedFile,
    BaseEntity,
    BaseIdentifiedEntity,
    ExternalReference,
    Note,
    OrganizationAuthor,
)

__all__ = [
    # Models flat list
    "AssociatedFile",
    "ExternalReference",
    "Note",
    "OrganizationAuthor",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
