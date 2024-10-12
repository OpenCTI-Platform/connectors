import logging
from re import search

import pycti
from countryinfo import CountryInfo
from pycti import Location as pycti_location
from pycti import StixCoreRelationship
from stix2 import (
    AutonomousSystem,
    DomainName,
    Identity,
    IPv4Address,
    IPv6Address,
    Location,
    Relationship,
)
from validators import domain as domain_validator

from .hostio_utils import extract_asn_number, get_tlp_marking, is_ipv4, is_ipv6

LOGGER = logging.getLogger(__name__)


class BaseStixTransformation:
    """Class to transform a Domain into a STIX DomainName object."""

    def __init__(self, author, marking_refs="TLP:WHITE", entity_id=None):
        """Initialize the class with the domain and entity id."""
        self.marking_refs = [get_tlp_marking(marking_refs)]
        self.entity_id = entity_id
        self.author = author
        self.stix_objects = []
        self.domain = None
        self.ip = None
        self.hostio_id = None
        self.labels = []

    def _create_autonomous_system(self, asn_data, relationship_id):
        """Transform ASN Data"""
        asn_id = None
        if isinstance(asn_data, str):
            as_number = search(r"AS\d+", asn_data)
            # Extracted AS number
            as_number = as_number.group() if as_number else None
            if as_number:
                asn_id = extract_asn_number(as_number)
        elif isinstance(asn_data, dict):
            # Return only the number for the asn_data.get('asn') value (e.g., AS15169 should be 15169) using regex.
            asn_id = extract_asn_number(asn_data.get("asn"))
        if asn_id:
            asn_sco = AutonomousSystem(
                number=asn_id,
                name=asn_id,
                object_marking_refs=self.marking_refs,
            )
            self.stix_objects.append(asn_sco)
            self._create_relationships(relationship_id, asn_sco.get("id"), "belongs-to")

    def _create_domain_observable(self, domain, entity_id):
        """Create the STIX DomainName object."""
        domain_name_sco = DomainName(
            value=domain,
            type="domain-name",
            resolves_to_refs=None if entity_id is None else [entity_id],
            object_marking_refs=self.marking_refs,
        )
        self._create_relationships(
            source_id=domain_name_sco.get("id"),
            target_id=entity_id,
            relation_type="resolves-to",
        )
        self.stix_objects.append(domain_name_sco)

    def _create_relationships(self, source_id, target_id, relation_type):
        """Add a STIX relationship to the list of STIX objects."""
        LOGGER.debug(
            f"Adding relationship: {relation_type}, source_id: {source_id}, target_id: {target_id}"
        )
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type=relation_type,
                source_ref=source_id,
                target_ref=target_id,
            ),
            type="relationship",
            relationship_type=relation_type,
            source_ref=source_id,
            target_ref=target_id,
            object_marking_refs=self.marking_refs,
            created_by_ref=self.author.id,
        )
        self.stix_objects.append(relationship)

    def _create_dns_stix_object_and_relationship(self, record_value, record_type):
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
            self._create_relationships(
                source_id=self.entity_id,
                target_id=stix_object.get("id"),
                relation_type="resolves-to",
            )

    def _transform_dns(self, dns_response):
        """Transform the DNS data from HostIO to STIX2."""
        for record_type in ["a", "aaaa", "cname", "mx", "ns"]:
            if dns_response.get(record_type):
                for record_value in dns_response.get(record_type):
                    self._create_dns_stix_object_and_relationship(
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
            self._create_relationships(
                source_id=self.entity_id,
                target_id=stix_object.get("id"),
                relation_type="resolves-to",
            )

    def _create_labels(self, privacy):
        for key in privacy:
            if isinstance(privacy[key], bool) and privacy[key] is True:
                self.labels.append(key)
            if isinstance(privacy[key], str) and privacy[key] != "":
                self.labels.append(privacy[key])

    def _create_company(self, company):
        """Create the STIX Organization object."""
        company_sco = Identity(
            id=pycti.Identity.generate_id(company.get("name"), "organization"),
            name=company.get("name"),
            identity_class="organization",
            object_marking_refs=self.marking_refs,
            created_by_ref=self.author.id,
        )
        self.stix_objects.append(company_sco)
        self._create_relationships(
            source_id=company_sco.get("id"),
            target_id=self.entity_id,
            relation_type="resolves-to",
        )

    def _create_location(self, country, city=None, location_lon_lat=None):
        """Create the STIX Location object."""
        # Create the STIX Country object.
        country_sco = Location(
            id=pycti_location.generate_id(country.get("name"), "Country"),
            name=country.get("name"),
            object_marking_refs=self.marking_refs,
            country=(
                country.get("name")
                if hasattr(country, "official_name")
                else country.get("name")
            ),
            latitude=(
                float(country.get("latlng")[0]) if country.get("latlng")[0] else None
            ),
            longitude=(
                float(country.get("latlng")[1]) if country.get("latlng")[1] else None
            ),
            region=country.get("subregion"),
            created_by_ref=self.hostio_id,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [
                    (
                        country.get("name")
                        if hasattr(country, "official_name")
                        else country.get("name")
                    )
                ],
            },
        )
        self.stix_objects.append(country_sco)
        self._create_relationships(
            source_id=self.entity_id,
            target_id=country_sco.get("id"),
            relation_type="located-at",
        )

        # If the city is None or empty, or the location_lon_lat is None or empty, then return.
        if city in (None, "") or location_lon_lat in (None, ""):
            return

        # Split the location_lon_lat value into latitude and longitude.
        location_split = location_lon_lat.split(",")
        if len(location_split) != 2:
            return

        # Create the STIX Location object.
        city_sco = Location(
            id=pycti_location.generate_id(city, "City"),
            name=city,
            object_marking_refs=self.marking_refs,
            country=(
                country.get("name")
                if hasattr(country, "official_name")
                else country.get("name")
            ),
            latitude=float(location_split[0]) if location_split[0] else None,
            longitude=float(location_split[1]) if location_split[1] else None,
            custom_properties={"x_opencti_location_type": "City"},
        )

        # Add the STIX Location object to the list of STIX objects.
        self.stix_objects.append(city_sco)
        self._create_relationships(
            source_id=city_sco.get("id"),
            target_id=country_sco.get("id"),
            relation_type="located-at",
        )
        self._create_relationships(
            source_id=self.entity_id,
            target_id=city_sco.get("id"),
            relation_type="located-at",
        )

    def _transform_ipinfo_object(self, ipinfo_object):
        """Transform the IPInfo data from HostIO to STIX2"""
        if "asn" in ipinfo_object:
            LOGGER.info(f"ASN data: {ipinfo_object.get('asn')}")
            self._create_autonomous_system(ipinfo_object.get("asn"), self.entity_id)
        elif (
            "org" in ipinfo_object
            and isinstance(ipinfo_object.get("org"), str)
            and ipinfo_object.get("org").startswith("AS")
        ):
            LOGGER.info(f"ASN data: {ipinfo_object.get('org')}")
            self._create_autonomous_system(ipinfo_object.get("org"), self.entity_id)
        if "privacy" in ipinfo_object:
            LOGGER.info(f"Privacy data: {ipinfo_object.get('privacy')}")
            self._create_labels(ipinfo_object.get("privacy"))
        if "company" in ipinfo_object:
            LOGGER.info(f"Company data: {ipinfo_object.get('company')}")
            self._create_company(ipinfo_object.get("company"))
        if "domains" in ipinfo_object:
            LOGGER.info(f"Domains data: {ipinfo_object.get('domains')}")
            for domain in ipinfo_object.get("domains"):
                self._create_domain_observable(domain=domain, entity_id=self.entity_id)
        if "country" in ipinfo_object:
            country = CountryInfo(ipinfo_object.get("country")).info()
            LOGGER.debug(f"Country data: {country}")
            if country:
                self._create_location(
                    country, ipinfo_object.get("city"), ipinfo_object.get("loc")
                )
        if "hostname" in ipinfo_object and domain_validator(
            ipinfo_object.get("hostname")
        ):
            LOGGER.info(f"Hostname data: {ipinfo_object.get('hostname')}")
            self._create_domain_observable(
                domain=ipinfo_object.get("hostname"), entity_id=self.entity_id
            )

    def get_stix_objects(self):
        """Return the list of STIX objects."""
        return self.stix_objects

    def get_labels(self):
        """Return the list of STIX object labels."""
        return self.labels


class HostIOIPtoDomainStixTransform(BaseStixTransformation):
    """Class to transform a Domain into a STIX DomainName object."""

    def __init__(self, domain, author, marking_refs="TLP:WHITE", entity_id=None):
        """Initialize the class with the domain and entity id."""
        super().__init__(marking_refs=marking_refs, author=author, entity_id=entity_id)
        if domain_validator(domain):
            self.domain = domain
        else:
            raise ValueError(f"Domain provided failed validation: {domain}")

        # Create STIX objects for the Domain Name and External Reference and add them to the list of STIX objects.
        self._create_domain_observable(domain=self.domain, entity_id=self.entity_id)


class HostIODomainStixTransformation(BaseStixTransformation):
    """Class to transform a Domain into a STIX DomainName object."""

    def __init__(self, domain_object, author, marking_refs="TLP:WHITE", entity_id=None):
        """Initialize the class with the domain and entity id."""
        super().__init__(marking_refs=marking_refs, author=author, entity_id=entity_id)
        self.domain_object = domain_object
        if hasattr(self.domain_object, "dns") and self.domain_object.dns is not {}:
            self._transform_dns(self.domain_object.dns)
        if (
            hasattr(self.domain_object, "ipinfo")
            and self.domain_object.ipinfo is not {}
        ):
            self._transform_ipinfo(self.domain_object.ipinfo)


class IPInfoStixTransformation(BaseStixTransformation):
    """Class to transform a Domain into a STIX DomainName object."""

    def __init__(self, ipinfo_object, author, marking_refs="TLP:WHITE", entity_id=None):
        """Initialize the class with the domain and entity id."""
        super().__init__(marking_refs=marking_refs, author=author, entity_id=entity_id)
        self.ipinfo_object = ipinfo_object

        LOGGER.debug(f"IPInfo data: {self.ipinfo_object}")
        # Create STIX objects for the Domain Name and External Reference and add them to the list of STIX objects.
        self._transform_ipinfo_object(self.ipinfo_object)
