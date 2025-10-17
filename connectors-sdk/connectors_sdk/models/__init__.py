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
    IPV6Address,
    Note,
    OrganizationAuthor,
    Report,
    Software,
)

__all__ = [
    # Models flat list
    "AssociatedFile",
    "ExternalReference",
    "DomainName",
    "File",
    "Indicator",
    "IPV4Address",
    "IPV6Address",
    "Note",
    "OrganizationAuthor",
    "Report",
    "Software",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
