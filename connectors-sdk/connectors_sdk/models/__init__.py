"""Offer models."""

from connectors_sdk.models.administrative_area import AdministrativeArea
from connectors_sdk.models.associated_file import AssociatedFile
from connectors_sdk.models.attack_pattern import AttackPattern
from connectors_sdk.models.autonomous_system import AutonomousSystem
from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.base_identified_object import BaseIdentifiedObject
from connectors_sdk.models.base_object import BaseObject
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.city import City
from connectors_sdk.models.country import Country
from connectors_sdk.models.domain_name import DomainName
from connectors_sdk.models.external_reference import ExternalReference
from connectors_sdk.models.file import File
from connectors_sdk.models.hostname import Hostname
from connectors_sdk.models.indicator import Indicator
from connectors_sdk.models.individual import Individual
from connectors_sdk.models.intrusion_set import IntrusionSet
from connectors_sdk.models.ipv4_address import IPV4Address
from connectors_sdk.models.ipv6_address import IPV6Address
from connectors_sdk.models.kill_chain_phase import KillChainPhase
from connectors_sdk.models.malware import Malware
from connectors_sdk.models.note import Note
from connectors_sdk.models.organization import Organization
from connectors_sdk.models.organization_author import OrganizationAuthor
from connectors_sdk.models.region import Region
from connectors_sdk.models.relationship import Relationship
from connectors_sdk.models.report import Report
from connectors_sdk.models.sector import Sector
from connectors_sdk.models.software import Software
from connectors_sdk.models.threat_actor_group import ThreatActorGroup
from connectors_sdk.models.tlp_marking import TLPMarking
from connectors_sdk.models.url import URL
from connectors_sdk.models.vulnerability import Vulnerability
from connectors_sdk.models.x509_certificate import X509Certificate

__all__ = [
    # Typing purpose
    "BaseIdentifiedObject",
    "BaseObject",
    "BaseAuthorEntity",
    "BaseIdentifiedEntity",
    "BaseObservableEntity",
    # Models flat list
    "AdministrativeArea",
    "AssociatedFile",
    "AttackPattern",
    "AutonomousSystem",
    "City",
    "Country",
    "DomainName",
    "ExternalReference",
    "File",
    "Hostname",
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
    "Region",
    "Relationship",
    "Report",
    "Sector",
    "Software",
    "ThreatActorGroup",
    "TLPMarking",
    "URL",
    "Vulnerability",
    "X509Certificate",
]
