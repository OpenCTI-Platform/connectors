from datetime import datetime
from typing import Optional

import stix2
from connectors_sdk.models import (
    DomainName,
    ExternalReference,
    Indicator,
    Malware,
    OrganizationAuthor,
    TLPMarking,
)
from connectors_sdk.models.enums import MalwareType, TLPLevel
from connectors_sdk.models.ipv4_address import IPV4Address
from external_import_connector.constants import (
    AuthorInfo,
    ExternalReferences,
    InfrastructureTypes,
)
from external_import_connector.models import (
    Infrastructure,
    NetworkTraffic,
    Relationship,
)
from pydantic import AwareDatetime


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, tlp_level: str):
        self.helper = helper
        self.tlp_marking = self.create_tlp_marking(TLPLevel(tlp_level))
        self.author = self.create_author()

    def create_author(self) -> stix2.Identity:
        """Create Author identity object."""
        return OrganizationAuthor(
            name=AuthorInfo.NAME,
            description=AuthorInfo.DESCRIPTION,
            markings=[self.tlp_marking],
            external_references=self.create_external_references(),
        )

    @staticmethod
    def create_external_references() -> list[stix2.ExternalReference]:
        external_reference = ExternalReference(
            source_name=ExternalReferences.SOURCE_NAME,
            url=ExternalReferences.URL,
            description=ExternalReferences.DESCRIPTION,
        )
        return [external_reference.to_stix2_object()]

    @staticmethod
    def create_tlp_marking(
        tlp_level: TLPLevel,
    ) -> TLPMarking:
        """Get the appropriate TLP marking definition for the given level.

        Args:
            tlp_level: TLP level string (e.g., "white", "clear", "green", "amber", "amber+strict", "red")

        Returns:
            STIX2 MarkingDefinition object
        """
        return TLPMarking(
            level=tlp_level,
        )

    def create_c2_infrastructure(
        self,
        name: str,
        infrastructure_types: str = InfrastructureTypes.COMMAND_AND_CONTROL,
        created: Optional[AwareDatetime] = None,
    ) -> Infrastructure:
        """Creates a Command and Control (C2) infrastructure object."""
        infrastructure = Infrastructure(
            name=name,
            infrastructure_types=infrastructure_types,
            author=self.author.id,
            tpl_marking=self.tlp_marking.id,
            created=created,
        )
        return infrastructure

    def create_ipv4_observable(self, ip: str) -> IPV4Address:
        """
        Creates an IPv4 address observable.
        """
        ipv4 = IPV4Address(
            value=ip,
            author=self.author,
            markings=[self.tlp_marking],
        )
        return ipv4

    def create_domain_observable(self, hostname: str) -> DomainName:
        """
        Creates a domain name observable.
        """
        domain = DomainName(
            value=hostname,
            author=self.author,
            markings=[self.tlp_marking],
        )
        return domain

    def create_url_indicator(
        self, scan_uri: str, timestamp: AwareDatetime
    ) -> Indicator:
        """
        Creates a URL indicator.
        """
        indicator = Indicator(
            name=scan_uri,
            valid_from=timestamp,
            author=self.author,
            markings=[self.tlp_marking],
            pattern=f"[url:value = '{scan_uri}']",
            pattern_type="stix",
        )
        return indicator

    def create_malware_object(
        self, malware_name: str, malware_subsystem: str
    ) -> Malware:
        """
        Creates a malware object.
        """
        malware = Malware(
            name=malware_name,
            types=(
                [MalwareType(malware_subsystem)]
                if malware_subsystem
                else [MalwareType("unknown")]
            ),
            author=self.author,
            markings=[self.tlp_marking],
            is_family=False,
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
            author=self.author.id,
            confidence=confidence,
            tpl_marking=self.tlp_marking.id,
        )
        return relationship
