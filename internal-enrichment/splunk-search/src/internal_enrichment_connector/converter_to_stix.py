import ipaddress

import stix2
from stix2.v21 import TLP_WHITE, TLP_GREEN, TLP_AMBER, TLP_RED
from .utils import is_domain_name
from pycti import (
    Identity,
    StixCoreRelationship,
    StixSightingRelationship,
    MarkingDefinition,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper):
        self.helper = helper
        self.tlp_white = TLP_WHITE
        self.tlp_green = TLP_GREEN
        self.tlp_amber = TLP_AMBER
        self.tlp_red = TLP_RED

    @staticmethod
    def create_author(tlp_id) -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        tlp_id = tlp_id if tlp_id is not None else TLP_RED["id"]
        author = stix2.Identity(
            id=Identity.generate_id(name="Splunk", identity_class="securityplatform"),
            allow_custom=True,
            name="Splunk",
            identity_class="securityplatform",
            security_platform_type="SIEM",
            description="Splunk is a software platform widely used for searching, monitoring, and analyzing machine-generated big data via a web-style interface. It enables security operations, IT operations, and business intelligence through log and event data aggregation, real-time analytics, and alerting capabilities.",
            external_references=[
                stix2.ExternalReference(
                    source_name="splunk",
                    url="https://www.splunk.com/",
                    description="Official website for Splunk, the Data Platform for the hybrid world.",
                )
            ],
            objectMarkingRefs=[tlp_id],
            x_opencti_type="SecurityPlatform",
        )
        return author

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> dict:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
        )
        return relationship

    # ===========================#
    # Other Examples
    # ===========================#

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv4
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_domain = true

        if is_valid_domain:
            return True
        else:
            return False

    def create_obs(self, value: str, obs_id: str = None) -> dict:
        """
        Create observable according to value given
        :param value: Value in string
        :param obs_id: Value of observable ID in string
        :return: Stix object for IPV4, IPV6 or Domain
        """
        if self._is_ipv6(value) is True:
            stix_ipv6_address = stix2.IPv6Address(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
            return stix_ipv6_address
        elif self._is_ipv4(value) is True:
            stix_ipv4_address = stix2.IPv4Address(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
            return stix_ipv4_address
        elif self._is_domain(value) is True:
            stix_domain_name = stix2.DomainName(
                id=obs_id if obs_id is not None else None,
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
            return stix_domain_name
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address nor DomainName: ",
                {"value": value},
            )

    def create_sighting(
        self, sighted_ref: str, author: dict, description: str, tlp: str = None
    ) -> dict:
        """
        Create a STIX Sighting object for a given observable or indicator.
        :param sighted_ref: ID of the sighted STIX object
        :param author: Author identity dictionary
        :param tlp: Optional TLP marking reference
        :return: STIX Sighting object
        """
        sighting = stix2.Sighting(
            allow_custom=True,
            id=StixSightingRelationship.generate_id(
                sighted_ref, author["id"], "sighting"
            ),
            sighting_of_ref=sighted_ref,
            created_by_ref=author["id"],
            x_opencti_score=80,
            x_opencti_description=description,
            object_marking_refs=[tlp],
            x_opencti_created_by_ref=author["id"],
        )
        return sighting

    def create_incident_from_result(
        self, result: dict, author: dict, tlp: str = None
    ) -> dict:
        """
        Create a STIX Incident object based on a Splunk result dictionary.
        :param result: A dictionary representing a result row from Splunk
        :param author: Author identity dictionary
        :param tlp: Optional TLP marking reference
        :return: STIX Incident object
        """
        title = result.get("alert", "Suspicious Activity Detected")
        description = result.get(
            "message", "Suspicious activity detected from Splunk result."
        )
        incident = stix2.Incident(
            name=title,
            description=description,
            created_by_ref=author["id"],
            custom_properties={
                "x_opencti_created_by_ref": author["id"],
                **({"object_marking_refs": [tlp]} if tlp else {}),
            },
        )
        return incident
