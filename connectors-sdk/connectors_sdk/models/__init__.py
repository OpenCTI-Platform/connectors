"""Offer models."""

from connectors_sdk.models.octi import (
    URL,
    AssociatedFile,
    BaseEntity,
    BaseIdentifiedEntity,
    DomainName,
    ExternalReference,
    File,
    Indicator,
    Individual,
    IPV4Address,
    IPV6Address,
    Malware,
    Note,
    OrganizationAuthor,
    Report,
    Software,
    Vulnerability,
)

__all__ = [
    # Models flat list
    "AssociatedFile",
    "ExternalReference",
    "DomainName",
    "File",
    "Indicator",
    "Individual",
    "IPV4Address",
    "IPV6Address",
    "Malware",
    "Note",
    "OrganizationAuthor",
    "Report",
    "Software",
    "URL",
    "Vulnerability",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
