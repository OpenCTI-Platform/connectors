"""Offer OpenCTI models."""

import warnings

from connectors_sdk.models import (
    URL,
    AssociatedFile,
    AttackPattern,
    BaseIdentifiedEntity,
)
from connectors_sdk.models import BaseObject as BaseEntity
from connectors_sdk.models import (
    City,
    Country,
    DomainName,
    ExternalReference,
    File,
    Indicator,
    Individual,
    IntrusionSet,
    IPV4Address,
    IPV6Address,
    KillChainPhase,
    Malware,
    Note,
    Organization,
    OrganizationAuthor,
    Relationship,
    Report,
    Sector,
    Software,
    ThreatActorGroup,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk.models.octi.relationships import (
    based_on,
    derived_from,
    has,
    indicates,
    located_at,
    related_to,
    targets,
)

warnings.warn(
    "The 'connectors_sdk.models.octi' module is deprecated and will be removed"
    "in future versions. Please use 'connectors_sdk.models' instead.",
    DeprecationWarning,
    stacklevel=2,
)


__all__ = [
    # Models flat list
    "AssociatedFile",
    "AttackPattern",
    "City",
    "Country",
    "DomainName",
    "ExternalReference",
    "File",
    "Indicator",
    "Individual",
    "IntrusionSet",
    "IPV4Address",
    "IPV6Address",
    "KillChainPhase",
    "Malware",
    "Note",
    "Organization",
    "OrganizationAuthor",
    "Relationship",
    "Report",
    "Sector",
    "Software",
    "ThreatActorGroup",
    "TLPMarking",
    "URL",
    "Vulnerability",
    # Relationship builders
    "based_on",
    "derived_from",
    "has",
    "indicates",
    "located_at",
    "related_to",
    "targets",
    # Typing purpose
    "BaseEntity",
    "BaseIdentifiedEntity",
]
