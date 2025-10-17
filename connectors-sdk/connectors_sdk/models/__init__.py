"""Offer models."""

from connectors_sdk.models.octi import (
    AssociatedFile,
    BaseEntity,
    BaseIdentifiedEntity,
    DomainName,
    ExternalReference,
    Indicator,
    Note,
    OrganizationAuthor,
    Report,
)

__all__ = [
    # Models flat list
    "AssociatedFile",
    "ExternalReference",
    "DomainName",
    "Indicator",
    "Note",
    "OrganizationAuthor",
    "Report",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
