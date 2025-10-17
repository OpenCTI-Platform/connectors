"""Offer models."""

from connectors_sdk.models.octi import (
    AssociatedFile,
    BaseEntity,
    BaseIdentifiedEntity,
    ExternalReference,
    OrganizationAuthor,
)

__all__ = [
    # Models flat list
    "AssociatedFile",
    "ExternalReference",
    "OrganizationAuthor",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
