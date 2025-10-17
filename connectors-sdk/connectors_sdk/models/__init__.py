"""Offer models."""

from connectors_sdk.models.octi import (
    URL,
    AssociatedFile,
    BaseEntity,
    BaseIdentifiedEntity,
    City,
    DomainName,
    ExternalReference,
    File,
    Indicator,
    Individual,
    IPV4Address,
    IPV6Address,
    Malware,
    Note,
    Organization,
    OrganizationAuthor,
    Report,
    Sector,
    Software,
    Vulnerability,
)

__all__ = [
    # Models flat list
    "AssociatedFile",
    "City",
    "DomainName",
    "ExternalReference",
    "File",
    "Indicator",
    "Individual",
    "IPV4Address",
    "IPV6Address",
    "Malware",
    "Note",
    "Organization",
    "OrganizationAuthor",
    "Report",
    "Sector",
    "Software",
    "URL",
    "Vulnerability",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
