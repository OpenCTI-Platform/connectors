"""
Provides use cases to convert
"""

import re
from typing import TYPE_CHECKING, Any, Literal

import stix2

from .config_variables import ConfigConnector
from .models.opencti import (
    Author,
    BaseEntity,
    DomainName,
    HasRelationship,
    Hostname,
    IPAddress,
    MACAddress,
    OperatingSystem,
    RelatedToRelationship,
    Software,
    System,
    Vulnerability,
)
from .models.tenable import Asset, Plugin, VulnerabilityFinding

if TYPE_CHECKING:
    from pycti import OpenCTIConnectorHelper


def parse_cpe_uri(cpe_str: str) -> dict[str, str]:
    """Parse CPE URI following format 1 or 2.3.

    Args:
        cpe_str: the CPE URI

    Returns:
        (dict[str|str]):  {"part": part, "vendor": vendor, "product": product}

    Examples:
        >>> dct = parse_cpe_uri("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
    """
    supported_patterns = {
        "cpe:/": r"^cpe:/(?P<part>[a-z]):(?P<vendor>[a-zA-Z0-9_\-]+):(?P<product>[a-zA-Z0-9_\-]+)",
        "cpe:2.3": r"^cpe:2\.3:(?P<part>[a-z]+):(?P<vendor>[^:]+):(?P<product>[^:]+)",
    }
    for key, supported_pattern in supported_patterns.items():
        if cpe_str.startswith(key):
            match = re.match(pattern=supported_pattern, string=cpe_str)
            if match is not None:
                return {
                    "part": match.group("part"),
                    "vendor": match.group("vendor"),
                    "product": match.group("product"),
                }
            raise ValueError("CPE URI is missing mandatory information.")
    raise NotImplementedError("Unknown CPE URI format")


def cvss3_severity_from_score(
    score: float,
) -> Literal["None", "Low", "Medium", "High", "Critical"]:
    """
    Determine the CVSS v3 severity rating based on the CVSS score.

    This function maps the CVSS score to its qualitative severity rating
    as defined by the CVSS v3 specification (Table 14).

    Severity ratings and corresponding score ranges:
      - None: 0.0
      - Low: 0.1 - 3.9
      - Medium: 4.0 - 6.9
      - High: 7.0 - 8.9
      - Critical: 9.0 - 10.0

    Args:
        score (float): The CVSS v3 score, which should be in the range 0.0 to 10.0.

    Returns:
        str: The severity rating ("None", "Low", "Medium", "High", or "Critical").

    Raises:
        ValueError: If the score is outside the valid range (0.0 - 10.0).

    References:
        https://www.first.org/cvss/v3.0/specification-document [consulted on September 30th, 2024]
    """
    match score:
        case 0.0:
            return "None"
        case _ if 0.1 <= score <= 3.9:
            return "Low"
        case _ if 4.0 <= score <= 6.9:
            return "Medium"
        case _ if 7.0 <= score <= 8.9:
            return "High"
        case _ if 9.0 <= score <= 10.0:
            return "Critical"
        case _:
            raise ValueError("Invalid CVSS score. It must be between 0.0 and 10.0.")


def tlp_marking_definition_handler(
    marking_definition: Literal[
        "TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"
    ],
) -> stix2.MarkingDefinition:
    """
    Handles Traffic Light Protocol (TLP) marking definitions and returns the
    corresponding STIX2 marking definition.

    Args:
        marking_definition (Literal["TLP:CLEAR", "TLP:WHITE", "TLP:GREEN",
        "TLP:AMBER", "TLP:RED"]): The TLP marking definition..

    Returns:
        stix2.MarkingDefinition: The corresponding STIX2 marking definition.

    Raises:
        ValueError: If the provided marking definition is not supported.
    """
    output = {
        "TLP:CLEAR": stix2.TLP_WHITE,  # "TLP:CLEAR" and "TLP:WHITE" map to the same marking
        "TLP:WHITE": stix2.TLP_WHITE,
        "TLP:GREEN": stix2.TLP_GREEN,
        "TLP:AMBER": stix2.TLP_AMBER,
        "TLP:RED": stix2.TLP_RED,
    }.get(marking_definition, None)
    if output is None:
        raise ValueError(f"Unsupported TLP marking: {marking_definition}.")
    return output


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.
    """

    def __init__(
        self,
        helper: "OpenCTIConnectorHelper",
        config: "ConfigConnector",
        default_marking: Literal[
            "TLP:CLEAR", "TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"
        ],
    ):
        self.helper = helper
        self.config = config
        self.author = ConverterToStix._make_author()
        self.object_marking_refs = [
            tlp_marking_definition_handler(default_marking)["id"]
        ]

    @staticmethod
    def _make_author() -> Author:
        return Author(
            name="Tenable-Vuln-Management",
            description="Tenable Vulnerability Management® (formerly known as Tenable.io) allows security and audit "
            "teams to share multiple Tenable Nessus, Tenable Nessus Agent, and Tenable Nessus Network "
            "Monitor scanners, scan schedules, scan policies, and scan results among an unlimited set of "
            "users or groups.",
            contact_information="https://www.tenable.com/about-tenable/contact-tenable",
            x_opencti_organization_type="vendor",
        )

    def _make_system(self, asset: Asset) -> System:
        return System(
            author=self.author,
            object_marking_refs=self.object_marking_refs,
            name=asset.hostname,
        )

    def _make_mac_address(self, asset: Asset) -> MACAddress | None:
        """Create a MACAddress object from an asset if a MAC address exists.

        Args:
            asset (Asset): The asset containing MAC address information.

        Returns:
            MACAddress | None: A MACAddress object if the MAC address is available, otherwise None.
        """
        if asset.mac_address is None:
            return None
        return MACAddress(
            author=self.author,
            object_marking_refs=self.object_marking_refs,
            value=asset.mac_address,
        )

    def _make_ipv4_address(self, asset: Asset) -> IPAddress:
        return IPAddress(
            author=self.author,
            object_marking_refs=self.object_marking_refs,
            version="v4",
            value=asset.ipv4,
            resolves_to_mac_addresses=(
                [self._make_mac_address(asset)]
                if asset.mac_address is not None
                else None
            ),
        )

    def _make_ipv6_address(self, asset: Asset) -> IPAddress | None:
        """Create an IPv6 address object for the given asset, if available.

        Args:
            asset (Asset): The asset containing the IPv6 address.

        Returns:
            IPAddress | None: An IPAddress object for the IPv6 address if available, otherwise None.
        """
        return (
            IPAddress(
                author=self.author,
                object_marking_refs=self.object_marking_refs,
                version="v6",
                value=asset.ipv6,
                resolves_to_mac_addresses=(
                    [self._make_mac_address(asset)]
                    if asset.mac_address is not None
                    else None
                ),
            )
            if asset.ipv6
            else None
        )

    def _make_hostname(self, asset: Asset) -> Hostname:
        return Hostname(
            author=self.author,
            object_marking_refs=self.object_marking_refs,
            value=asset.hostname,
        )

    def make_operating_systems(self, asset: Asset) -> list[OperatingSystem]:
        return [
            OperatingSystem(
                author=self.author,
                object_marking_refs=self.object_marking_refs,
                name=name,
            )
            for name in asset.operating_system
        ]

    def _make_domain_name(self, asset: Asset) -> DomainName | None:
        """Create a DomainName object for the given asset, if available.

        Args:
            asset (Asset): The asset containing the fully qualified domain name (FQDN).

        Returns:
            DomainName | None: A DomainName object for the asset if an FQDN is available, otherwise None.
        """

        return (
            DomainName(
                author=self.author,
                object_marking_refs=self.object_marking_refs,
                value=asset.fqdn,
                resolves_to_domain_names=None,
                resolves_to_ips=[self._make_ipv4_address(asset)]
                + ([self._make_ipv6_address(asset)] if asset.ipv6 is not None else []),
            )
            if asset.fqdn
            else None
        )

    def process_asset(self, asset: Asset) -> dict[str, Any]:
        system = self._make_system(asset=asset)
        observables = [
            obs
            for obs in (
                self._make_ipv4_address(asset=asset),
                self._make_hostname(asset=asset),
                # optional
                self._make_mac_address(asset=asset),
                self._make_ipv6_address(asset=asset),
                self._make_domain_name(asset=asset),
            )
            if obs is not None
        ]
        observables += self.make_operating_systems(asset=asset)  # A list

        relationships = [
            RelatedToRelationship(
                author=self.author,
                created=None,
                modified=None,
                description=None,
                source_ref=system.id,
                target_ref=obs.id,
                start_time=None,
                stop_time=None,
                confidence=None,
                object_marking_refs=self.object_marking_refs,
            )
            for obs in observables
        ]
        return {
            "system": system,
            "observables": observables,
            "relationships": relationships,
        }

    def _make_targeted_software_s(self, plugin: Plugin) -> list[Software]:
        """Create a list of Software objects based on the CPE URIs in the plugin.

        Args:
            plugin (Plugin): The plugin containing CPE URIs.

        Returns:
            list[Software]: A list of Software objects extracted from the CPE URIs in the plugin.
        """

        return (
            [
                Software(
                    author=self.author,
                    object_marking_refs=self.object_marking_refs,
                    name=cpe_data["product"],
                    vendor=cpe_data["vendor"],
                    cpe=cpe_uri,
                )
                for cpe_uri in plugin.cpe
                for cpe_data in [parse_cpe_uri(cpe_uri)]
            ]
            if plugin.cpe is not None
            else []
        )

    def _make_vulnerabilities(self, plugin: Plugin) -> list[Vulnerability]:
        """
        Create a list of Vulnerability objects from the given plugin.

        Args:
            plugin (Plugin): The plugin containing vulnerability information such as CVEs and CVSS scores.

        Returns:
            list[Vulnerability]: A list of Vulnerability objects.
        """

        base = dict(
            author=self.author,
            object_marking_refs=self.object_marking_refs,
            created=plugin.publication_date,
            modified=plugin.modification_date,
            description=plugin.description,
            confidence=None,
            cvss3_score=plugin.cvss3_base_score,
            cvss3_severity=(
                cvss3_severity_from_score(plugin.cvss3_base_score)
                if plugin.cvss3_base_score
                else None
            ),
        )
        cvss3_vector = plugin.cvss3_vector
        details = (
            {
                "cvss3_attack_vector": cvss3_vector.access_vector,
                "cvss3_integrity_impact": cvss3_vector.integrity_impact,
                "cvss3_availability_impact": cvss3_vector.availability_impact,
                "cvss3_confidentiality_impact": cvss3_vector.confidentiality_impact,
            }
            if cvss3_vector
            else {}
        )

        return (
            [Vulnerability(name=cve, **base, **details) for cve in plugin.cve]
            if plugin.cve
            else [Vulnerability(name=plugin.name, **base, **details)]
        )

    def process_plugin(self, plugin: Plugin) -> dict[str, Any]:
        software_s = self._make_targeted_software_s(plugin=plugin)
        vulnerabilities = self._make_vulnerabilities(plugin=plugin)

        relationships_soft_vulns = [
            HasRelationship(
                author=self.author,
                created=None,
                modified=None,
                description=None,
                source_ref=software.id,
                target_ref=vulnerability.id,
                start_time=None,
                stop_time=None,
                confidence=None,
                object_marking_refs=self.object_marking_refs,
            )
            for software in software_s
            for vulnerability in vulnerabilities
        ]
        return {
            "vulnerabilities": vulnerabilities,
            "software_s": software_s,
            "relationships": relationships_soft_vulns,
        }

    def process_vuln_finding(
        self, vuln_finding: VulnerabilityFinding
    ) -> list[BaseEntity]:
        """
        Process a vulnerability finding by extracting related system and vulnerability objects,
        and establish relationships between them.

        Args:
            vuln_finding (VulnerabilityFinding): The vulnerability finding containing asset and plugin data.

        Returns:
            list[BaseEntity]: A list of BaseEntity objects including systems, vulnerabilities, observables, and relationships.
        """
        system_related_objects = self.process_asset(vuln_finding.asset)
        vulnerability_related_objects = self.process_plugin(vuln_finding.plugin)

        system = system_related_objects["system"]
        vulnerabilities = vulnerability_related_objects["vulnerabilities"]

        system_to_vulnerabilities = [
            HasRelationship(
                author=self.author,
                created=None,
                modified=None,
                description=None,
                source_ref=system.id,
                target_ref=vulnerability.id,
                start_time=vuln_finding.first_found,
                stop_time=(
                    vuln_finding.last_found
                    if vuln_finding.state.lower() == "fixed"
                    else None
                ),  # fixed, open or reopen
                confidence=None,
                object_marking_refs=self.object_marking_refs,
                external_references=[
                    {
                        "source_name": "Tenable Vulnerability Management",
                        "url": f"{self.config.tio_api_base_url}/tio/app.html#/findings/host-vulnerabilities/details/"
                        f"{vuln_finding.finding_id}/asset/{vuln_finding.asset.uuid}/asset-affected",
                        "description": "A detailed analysis of the vulnerability.",
                    }
                ],
                # x_octi_workflow_id
            )
            for vulnerability in vulnerabilities
        ]

        return list(
            set(
                [self.author, system]
                + vulnerabilities
                + system_to_vulnerabilities
                + system_related_objects["observables"]
                + system_related_objects["relationships"]
                + vulnerability_related_objects["software_s"]
                + vulnerability_related_objects["relationships"]
            )
        )
