from datetime import datetime

import stix2

from .models import (
    URL,
    Author,
    DomainName,
    Infrastructure,
    IPv4Address,
    Malware,
    NetworkTraffic,
    Relationship,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper):
        self.helper = helper
        self.author = self.create_author()
        self.external_reference = self.create_external_reference()

    @staticmethod
    def create_external_reference() -> list:
        """
        Create external reference
        :return: External reference STIX2 list
        """
        external_reference = stix2.ExternalReference(
            source_name="Hunt IO",
            url="https://hunt.io",
            description="Hunt IO",
        )
        return [external_reference]

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = Author("Hunt IO", "Hunt IO").stix2_object
        assert author is not None

        return author

    def create_c2_infrastructure(
        self,
        name: str,
        infrastructure_types: str,
        created: datetime | None = None,
    ):
        """
        Creates a Command and Control (C2) infrastructure object.
        """
        infrastructure = Infrastructure(
            name, infrastructure_types, self.author["id"], created
        )
        return infrastructure

    def create_ipv4_observable(self, ip: str) -> IPv4Address:
        """
        Creates an IPv4 address observable.
        """
        ipv4 = IPv4Address(ip)
        return ipv4

    def create_domain_observable(self, hostname: str) -> DomainName:
        """
        Creates an domain name observable.
        """
        domain = DomainName(hostname)
        return domain

    def create_url_indicator(self, scan_uri: str, timestamp: datetime) -> URL:
        """
        Creates an URL indicator.
        """
        indicator = URL(scan_uri, timestamp, self.author["id"])
        return indicator

    def create_malware_object(
        self, malware_name: str, malware_subsystem: str
    ) -> Malware:
        """
        Creates a malware object.
        """
        malware = Malware(malware_name, malware_subsystem)
        return malware

    def create_network_traffic(
        self, port: int | None, src_ref: str | None
    ) -> NetworkTraffic:
        """
        Creates a network traffic object.
        """
        network_traffic = NetworkTraffic(port, src_ref)
        return network_traffic

    def create_relationship(
        self,
        relationship_type: str,
        created: datetime,
        source_id: str,
        target_id: str | None,
        confidence: int,
    ) -> Relationship:
        """
        Creates a relationship object.
        """
        relationship = Relationship(
            relationship_type,
            created,
            source_id,
            target_id,
            self.author["id"],
            confidence,
        )
        return relationship
