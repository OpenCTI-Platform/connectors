"""Offer OpenCTI models."""

from connectors_sdk.models.base_entity import BaseEntity
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.external_reference import ExternalReference
from connectors_sdk.models.octi._common import AssociatedFile, TLPMarking
from connectors_sdk.models.octi.activities.analyses import Note, Report
from connectors_sdk.models.octi.activities.observations import (
    URL,
    DomainName,
    File,
    Indicator,
    IPV4Address,
    IPV6Address,
    Software,
)
from connectors_sdk.models.octi.knowledge.arsenal import Malware, Vulnerability
from connectors_sdk.models.octi.knowledge.entities import (
    Individual,
    Organization,
    Sector,
)
from connectors_sdk.models.octi.knowledge.locations import City, Country
from connectors_sdk.models.octi.knowledge.techniques import AttackPattern
from connectors_sdk.models.octi.knowledge.threats import IntrusionSet, ThreatActorGroup
from connectors_sdk.models.octi.relationships import (
    Relationship,
    based_on,
    derived_from,
    has,
    indicates,
    located_at,
    related_to,
    targets,
)
from connectors_sdk.models.octi.settings.taxonomies import KillChainPhase
from connectors_sdk.models.organization_author import OrganizationAuthor

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
