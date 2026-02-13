import ipaddress
from typing import Literal, Optional

from connectors_sdk.models import (
    Indicator,
    Malware,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
)
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
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `tlp_level`) if necessary.

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

    def convert_ip(self, ip: str) -> Indicator:

        if self._is_ipv4(ip):
            ip_pattern = f"[ipv4-addr:value = '{ ip }']"
            ip_type = "IPv4-Addr"
            ip_indicator = self.create_indicator(ip, ip_pattern, ip_type)

        elif self._is_ipv6(ip):
            ip_pattern = f"[ipv6-addr:value = '{ ip }']"
            ip_type = "IPv6-Addr"
            ip_indicator = self.create_indicator(ip, ip_pattern, ip_type)

        else:
            ip_indicator = None

        return ip_indicator

    def create_indicator(self, ip: str, ip_pattern: str, ip_type: str) -> Indicator:

        ip_indicator = Indicator(
            name=ip,
            pattern=ip_pattern,
            pattern_type="stix",
            main_observable_type=ip_type,
            create_observables=True,
            author=self.author,
            markings=[self.tlp_marking],
        )

        return ip_indicator

    @staticmethod
    def create_author() -> dict:
        """
        Create Author
        """
        author = OrganizationAuthor(name="MontySecurity")
        return author

    @staticmethod
    def _create_tlp_marking(level):
        """
        Create TLPMarking object
        """
        tlp_marking = TLPMarking(level=level)
        return tlp_marking

    def create_relationship(
        self,
        relationship_type: str,
        source_obj,
        target_obj,
        start_time: Optional[str] = None,
        stop_time: Optional[str] = None,
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
