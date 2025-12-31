from connectors_sdk.models import AutonomousSystem, Country, Hostname, IPV4Address
from connectors_sdk.models.enums import RelationshipType
from connectors_sdk.models.ipv6_address import IPV6Address

from .enricher import Enricher


class IPEnricher(Enricher):
    """
    Base enricher for IPv4 and IPv6.
    """

    @property
    def ip_without_cidr(self) -> str:
        """
        Return IP value without CIDR suffix.

        Example:
            "192.168.1.10/24" → "192.168.1.10"
        """
        return self.stix_entity.get("value").split("/")[0]

    def build_ip(self) -> None:
        """
        Create the base IP observable and add it to the bundle.
        """
        self.ip = self.OCTI_CLASS(
            value=self.ip_without_cidr,
            score=self.enriched_data.get("sp_risk_score"),
        )
        self.source = self.ip
        self.build_labels()
        self.octi_observables.append(self.source)

    def build_subnet(self) -> None:
        """
        Adds subnet enriched data to the octi bundle
        """
        subnet_data = self.enriched_data.get("subnet")
        if not subnet_data:
            return
        if subnet_data == self.ip_without_cidr:
            return
        self.helper.connector_logger.debug(f"building Subnet: {subnet_data}")
        subnet = self.OCTI_CLASS(
            value=subnet_data,
            score=self.enriched_data.get("subnet_reputation_score"),
        )
        self.add_target_and_relationship(subnet, RelationshipType.RELATED_TO, "Subnet")

    def build_asn(self) -> None:
        """
        Adds ASN enriched data to the octi bundle
        """
        asn_number = self.enriched_data.get("asn")
        if not asn_number:
            return
        asn = AutonomousSystem(
            number=asn_number,
            name=self.enriched_data.get("asname"),
            score=self.enriched_data.get("asn_reputation_score"),
        )
        self.add_target_and_relationship(asn, "belongs-to", "ASN")

    def build_location(self) -> None:
        """
        Adds geo location enriched data to the octi bundle
        """
        country_name = self.enriched_data.get("ip_location", {}).get("country_name")
        if not country_name:
            return
        self.helper.connector_logger.debug(f"building Country: {country_name}")
        country = Country(name=country_name)
        self.add_target_and_relationship(
            country, RelationshipType.RELATED_TO, country_name
        )

    def build_ptr(self) -> None:
        """
        Adds PTR enriched data to the octi bundle
        """

        ptr = self.enriched_data.get("ip_ptr")
        if not ptr:
            return
        self.helper.connector_logger.debug(f"building PTR: {ptr}")
        hostname = Hostname(value=ptr)
        self.add_target_and_relationship(hostname, RelationshipType.RELATED_TO, "PTR")

    def enrich(self) -> None:
        """
        Main enrichment pipeline for IPv4 and IPv6.
        Fetches SilentPush data, populates enriched_data, and builds all related observables.
        """
        json_response = self.client.get_enrichment_data(
            self.API_TYPE, self.ip_without_cidr
        )
        self.enriched_data = json_response.get("ip2asn")[0]
        self.helper.connector_logger.debug(f"self.enriched_data: {self.enriched_data}")

        self.build_ip()
        self.build_location()
        self.build_asn()
        self.build_subnet()
        self.build_ptr()
        self.build_certificates()
        self.build_favicon()

    def extract_labels(self) -> dict:
        """
        Extract all boolean flags and return (value, color).
        """
        return {
            "known_benign": (
                self.enriched_data.get("benign_info", {}).get("known_benign"),
                "#4caf50",
            ),
            "is_proxy": (
                self.enriched_data.get("ip_flags", {}).get("is_proxy"),
                "#af4c68",
            ),
            "is_sinkhole": (
                self.enriched_data.get("ip_flags", {}).get("is_sinkhole"),
                "#a1713a",
            ),
            "is_vpn": (
                self.enriched_data.get("ip_flags", {}).get("is_vpn"),
                "#782b2e",
            ),
            "ip_has_expired_certificate": (
                self.enriched_data.get("ip_has_expired_certificate"),
                "#e09109",
            ),
            "ip_has_open_directory": (
                self.enriched_data.get("ip_has_open_directory"),
                "#4f96bd",
            ),
            "ip_is_dsl_dynamic": (
                self.enriched_data.get("ip_is_dsl_dynamic"),
                "#841a99",
            ),
            "ip_is_ipfs_node": (self.enriched_data.get("ip_is_ipfs_node"), "#070354"),
            "ip_is_tor_exit_node": (
                self.enriched_data.get("ip_is_tor_exit_node"),
                "#c795cc",
            ),
            "known_sinkhole_ip": (
                self.enriched_data.get("sinkhole_info", {}).get("known_sinkhole_ip"),
                "#c75f98",
            ),
        }


class IPv4Enricher(IPEnricher):
    """IPv4 enricher implementation."""

    API_TYPE = "ipv4"
    OCTI_CLASS = IPV4Address


class IPv6Enricher(IPEnricher):
    """IPv6 enricher implementation."""

    API_TYPE = "ipv6"
    OCTI_CLASS = IPV6Address
