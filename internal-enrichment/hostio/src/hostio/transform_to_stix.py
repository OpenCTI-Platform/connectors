from stix2 import DomainName, Relationship, IPv4Address, IPv6Address, AutonomousSystem, ExternalReference
from validators import domain as domain_validator

from .hostio_utils import get_tlp_marking, is_ipv4, is_ipv6, extract_asn_number
import logging
import pycountry


from pycti import (
    Location,
    StixCoreRelationship,
)

LOGGER = logging.getLogger(__name__)


class HostIOIPtoDomainStixTransform:
    """Class to transform a Domain into a STIX DomainName object."""

    def __init__(self, domain, marking_refs="TLP:WHITE", entity_id=None):
        """Initialize the class with the domain and entity id."""
        self.marking_refs = [get_tlp_marking(marking_refs)]
        if domain_validator(domain):
            self.domain = domain
        else:
            raise ValueError(f"Domain provided failed validation: {domain}")
        self.entity_id = entity_id

        # Create STIX objects for the Domain Name and External Reference and add them to the list of STIX objects.
        self.stix_objects = self._create_domain_observable()

    def _create_domain_observable(self):
        """Create the STIX DomainName object."""
        domain_name_sco = DomainName(
            value=self.domain,
            type="domain-name",
            resolves_to_refs=None if self.entity_id is None else [self.entity_id],
            object_marking_refs=self.marking_refs,
        )
        relationship_sro = self._create_relationships(domain_name_sco.get('id'))
        return [domain_name_sco, relationship_sro]
    
    def _create_relationships(self, domain_id):
        """Create the STIX Relationship object."""
        return Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type="resolves-to",
                source_ref=domain_id,
                target_ref=self.entity_id,
                ),
            type="relationship",
            source_ref=domain_id,
            target_ref=self.entity_id,
            relationship_type="resolves-to",
        )

    def get_stix_objects(self):
        """Return the list of STIX objects."""
        return self.stix_objects


class HostIODomainStixTransformation:
    """Class to transform a Domain into a STIX DomainName object."""
    
    def __init__(self, domain_object, marking_refs="TLP:WHITE", entity_id=None):
        """Initialize the class with the domain and entity id."""
        self.marking_refs = [get_tlp_marking(marking_refs)]
        self.domain_object = domain_object
        self.entity_id = entity_id
        self.stix_objects = []
        if hasattr(self.domain_object, "dns") and self.domain_object.dns is not {}:
            self._transform_dns(self.domain_object.dns)
        if hasattr(self.domain_object, "ipinfo") and self.domain_object.ipinfo is not {}:
            self._transform_ipinfo(self.domain_object.ipinfo)

    def _add_relationship(self, source_id, target_id, relation_type):
        """Add a STIX relationship to the list of STIX objects."""
        LOGGER.debug(f"Adding relationship: {relation_type}, source_id: {source_id}, target_id: {target_id}")
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type=relation_type,
                source_ref=source_id,
                target_ref=target_id,
                ),
            type="relationship",
            relationship_type=relation_type,
            source_ref=source_id,
            target_ref=target_id
        )
        self.stix_objects.append(relationship)

    def _add_autonomous_system(self, asn_data, relationship_id):
        """"""
        # Return only the number for the asn_data.get('asn') value (e.g., AS15169 should be 15169) using regex.
        asn_id = extract_asn_number(asn_data.get('asn'))
        if asn_id is not None:
            asn_sco = AutonomousSystem(
                number=asn_id,
                name=asn_data.get('name') if 'name' in asn_data else None,
                object_marking_refs=self.marking_refs,
            )
            self.stix_objects.append(asn_sco)
            self._add_relationship(relationship_id, asn_sco.get('id'), 'belongs-to')

    def _add_dns_stix_object_and_relationship(self, record_value, record_type):
        """Add a STIX object and its relationship to the list of STIX objects."""
        stix_object = None
        if record_type == "a" and is_ipv4(record_value):
            stix_object = IPv4Address(value=record_value)
        elif record_type == "aaaa" and is_ipv6(record_value):
            stix_object = IPv6Address(value=record_value)
        elif record_type in ["cname"]:
            stix_object = DomainName(value=record_value)
        else:
            LOGGER.warning(f"Unsupported DNS record type: {record_type}")
            return

        if stix_object and hasattr(stix_object, "id"):
            self.stix_objects.append(stix_object)
            self._add_relationship(source_id=self.entity_id, target_id=stix_object.get("id"), relation_type="resolves-to")

    def _transform_dns(self, dns_response):
        """Transform the DNS data from HostIO to STIX2."""
        for record_type in ["a", "aaaa", "cname", "mx", "ns"]:
            if dns_response.get(record_type):
                for record_value in dns_response.get(record_type):
                    self._add_dns_stix_object_and_relationship(
                        record_value, record_type
                    )

    def _transform_ipinfo(self, ipinfo_response):
        """Transform the IPInfo data from HostIO to STIX2"""
        for ip, info in ipinfo_response.items():
            if is_ipv6(ip):
                LOGGER.info(f"IPv6 data: {info}")
                stix_object = IPv6Address(value=ip)
            elif is_ipv4(ip):
                LOGGER.info(f"IPv4 data: {info}")
                stix_object = IPv4Address(value=ip)
            else:
                LOGGER.info(f"Invalid IP: {ip}")
                continue  # Skip invalid IP
            self.stix_objects.append(stix_object)
            self._add_relationship(source_id=self.entity_id, target_id=stix_object.get('id'), relation_type='resolves-to')

            # Add Autonomous System object and relationship.
            if 'asn' in info:
                self._add_autonomous_system(asn_data=info.get('asn'), relationship_id=stix_object.get('id'))

    def get_stix_objects(self):
        """Return the list of STIX objects."""
        LOGGER.info(f"STIX objects count: {len(self.stix_objects)}")
        return self.stix_objects