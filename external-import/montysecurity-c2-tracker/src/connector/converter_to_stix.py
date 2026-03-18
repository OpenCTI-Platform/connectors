import ipaddress
from datetime import datetime
from typing import Literal

from connectors_sdk.models import (
    IPV4Address,
    IPV6Address,
    Malware,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
from connectors_sdk.models.enums import RelationshipType
from pycti import (
    OpenCTIConnectorHelper,
)


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
        - `generate_id()` methods from `pycti` library MUST be used to generate the `id` of each entity (except observables),
        e.g. `pycti.Identity.generate_id(name="Source Name", identity_class="organization")` for a STIX Identity.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ):
        """
        Initialize the converter with necessary configuration.
        The connector helper is injected for logging and tracing.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (str): The TLP level to add to the created STIX entities.
        """
        self.helper = helper

        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())

    def convert_malware(self, malware: str) -> Malware:

        malware_name = malware.split(" IPs.txt")[0]
        self.helper.connector_logger.info(
            "Looking at malware. ", {"malware": malware_name}
        )

        malware_stix = Malware(
            name=malware_name,
            is_family=True,
            author=self.author,
            markings=[self.tlp_marking],
        )

        return malware_stix

    def convert_ip(self, ip: str) -> IPV4Address | IPV6Address | None:

        if self._is_ipv4(ip):
            ip_indicator = IPV4Address(value=ip)

        elif self._is_ipv6(ip):
            ip_indicator = IPV6Address(value=ip)

        else:
            ip_indicator = None

        return ip_indicator

    @staticmethod
    def create_author() -> OrganizationAuthor:
        """
        Create Author
        """
        return OrganizationAuthor(name="MontySecurity")

    @staticmethod
    def _create_tlp_marking(level) -> TLPMarking:
        """
        Create TLPMarking object
        """
        return TLPMarking(level=level)

    def create_relationship(
        self,
        relationship_type: RelationshipType,
        source_obj,
        target_obj,
        start_time: datetime | None = None,
        stop_time: datetime | None = None,
    ) -> Relationship:
        """
        Creates Relationship object
        """
        return Relationship(
            type=relationship_type,
            source=source_obj,
            target=target_obj,
            author=self.author,
            start_time=start_time,
            stop_time=stop_time,
            markings=[self.tlp_marking],
        )

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
