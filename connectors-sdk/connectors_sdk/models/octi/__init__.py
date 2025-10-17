"""Offer OpenCTI models."""

from connectors_sdk.models.associated_file import AssociatedFile
from connectors_sdk.models.attack_pattern import AttackPattern
from connectors_sdk.models.base_entity import BaseEntity
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.city import City
from connectors_sdk.models.country import Country
from connectors_sdk.models.domain_name import DomainName
from connectors_sdk.models.external_reference import ExternalReference
from connectors_sdk.models.file import File
from connectors_sdk.models.indicator import Indicator
from connectors_sdk.models.individual import Individual
from connectors_sdk.models.ipv4_address import IPV4Address
from connectors_sdk.models.ipv6_address import IPV6Address
from connectors_sdk.models.malware import Malware
from connectors_sdk.models.note import Note
from connectors_sdk.models.octi._common import TLPMarking
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
from connectors_sdk.models.organization import Organization
from connectors_sdk.models.organization_author import OrganizationAuthor
from connectors_sdk.models.report import Report
from connectors_sdk.models.sector import Sector
from connectors_sdk.models.software import Software
from connectors_sdk.models.url import URL
from connectors_sdk.models.vulnerability import Vulnerability

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
