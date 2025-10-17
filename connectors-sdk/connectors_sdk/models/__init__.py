"""Offer models."""

from connectors_sdk.models.octi import (
    BaseEntity,
    BaseIdentifiedEntity,
    ExternalReference,
    OrganizationAuthor,
)

__all__ = [
    # Models flat list
    "ExternalReference",
    "OrganizationAuthor",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
