"""Offer models."""

from connectors_sdk.models.octi import (
    AssociatedFile,
    BaseEntity,
    BaseIdentifiedEntity,
    DomainName,
    ExternalReference,
    File,
    Indicator,
    IPV4Address,
    Note,
    OrganizationAuthor,
    Report,
)

__all__ = [
    # Models flat list
    "AssociatedFile",
    "ExternalReference",
    "DomainName",
    "File",
    "Indicator",
    "IPV4Address",
    "Note",
    "OrganizationAuthor",
    "Report",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
