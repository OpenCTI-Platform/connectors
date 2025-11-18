from datetime import datetime
from typing import Literal, Optional

import pycti
import stix2
from external_import_connector.constants import (
    AuthorInfo,
    ExternalReferences,
    InfrastructureTypes,
)
from external_import_connector.exceptions import InvalidTlpLevelError
from external_import_connector.models import (
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
        self.tlp_marking = self.create_tlp_marking(
            self.helper.config["connector_hunt_io"]["tlp_level"]
        )
        self.author = self.create_author()

    def create_author(self) -> stix2.Identity:
        """Create Author identity object."""
        return Author(
            name=AuthorInfo.NAME,
            description=AuthorInfo.DESCRIPTION,
            tpl_marking=self.tlp_marking.id,
            external_references=self.create_external_references(),
        ).stix2_object

    @staticmethod
    def create_external_references() -> list[stix2.ExternalReference]:
        external_reference = stix2.ExternalReference(
            source_name=ExternalReferences.SOURCE_NAME,
            url=ExternalReferences.URL,
            description=ExternalReferences.DESCRIPTION,
        )
        return [external_reference]

    @staticmethod
    def create_tlp_marking(
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ) -> stix2.MarkingDefinition:
        """Get the appropriate TLP marking definition for the given level.

        Args:
            tlp_level: TLP level string (e.g., "white", "clear", "green", "amber", "amber+strict", "red")

        Returns:
            STIX2 MarkingDefinition object

        Raises:
            InvalidTlpLevelError: If the TLP level is not recognized
        """
        tlp_mappings = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "red": stix2.TLP_RED,
        }

        if tlp_level in tlp_mappings:
            return tlp_mappings[tlp_level]

        if tlp_level == "amber+strict":
            return stix2.MarkingDefinition(
                id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            )

        raise InvalidTlpLevelError(f"Invalid TLP level: {tlp_level}")

    def create_c2_infrastructure(
        self,
        name: str,
        infrastructure_types: str = InfrastructureTypes.COMMAND_AND_CONTROL,
        created: Optional[datetime] = None,
    ) -> Infrastructure:
        """Creates a Command and Control (C2) infrastructure object."""
        infrastructure = Infrastructure(
            name=name,
            infrastructure_types=infrastructure_types,
            author=self.author["id"],
            tpl_marking=self.tlp_marking.id,
            created=created,
        )
        return infrastructure

    def create_ipv4_observable(self, ip: str) -> IPv4Address:
        """
        Creates an IPv4 address observable.
        """
        ipv4 = IPv4Address(
            value=ip,
            author=self.author.id,
            tpl_marking=self.tlp_marking.id,
        )
        return ipv4

    def create_domain_observable(self, hostname: str) -> DomainName:
        """
        Creates an domain name observable.
        """
        domain = DomainName(
            hostname,
            author=self.author.id,
            tpl_marking=self.tlp_marking.id,
        )
        return domain

    def create_url_indicator(self, scan_uri: str, timestamp: datetime) -> URL:
        """
        Creates an URL indicator.
        """
        indicator = URL(
            scan_uri=scan_uri,
            valid_from=timestamp,
            author_id=self.author["id"],
            tpl_marking=self.tlp_marking.id,
        )
        return indicator

    def create_malware_object(
        self, malware_name: str, malware_subsystem: str
    ) -> Malware:
        """
        Creates a malware object.
        """
        malware = Malware(
            malware_name=malware_name,
            malware_subsystem=malware_subsystem,
            author=self.author.id,
            tpl_marking=self.tlp_marking.id,
        )
        return malware

    def create_network_traffic(
        self, port: int | None, src_ref: str | None
    ) -> NetworkTraffic:
        """
        Creates a network traffic object.
        """
        network_traffic = NetworkTraffic(
            port=port,
            src_ref=src_ref,
            author=self.author.id,
            tpl_marking=self.tlp_marking.id,
        )
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
            relationship_type=relationship_type,
            created=created,
            source_id=source_id,
            target_id=target_id,
            author=self.author["id"],
            confidence=confidence,
            tpl_marking=self.tlp_marking.id,
        )
        return relationship
