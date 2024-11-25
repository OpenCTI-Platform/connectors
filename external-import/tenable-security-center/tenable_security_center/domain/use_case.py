# isort: skip_file # Skipping this file to prevent isort from removing type ignore comments for untyped imports
"""Provides the use case classes for the Tenable Security Center integration."""

import ipaddress
from typing import TYPE_CHECKING, Optional

import validators

from tenable_security_center.domain.entities import (
    Author,
    DomainName,
    ExternalReference,
    HasRelationship,
    IPAddress,
    MACAddress,
    OperatingSystem,
    RelatedToRelationship,
    Software,
    System,
    Vulnerability,
)

if TYPE_CHECKING:
    from pycti.connector.opencti_connector_helper import (  # type: ignore[import-untyped]
        OpenCTIConnectorHelper,
    )
    from stix2 import TLPMarking  # type: ignore[import-untyped]
    from stix2.v21 import (  # type: ignore[import-untyped]
        _STIXBase21,  # stix2 does not provide stubs
    )

    from tenable_security_center.domain.entities import BaseEntity, Observable
    from tenable_security_center.ports.asset import (
        AssetPort,
        AssetsChunkPort,
        CVEPort,
        FindingPort,
    )


class ConverterToStix:
    """Provides methods for converting various types of input data into STIX 2.1 objects."""

    def __init__(
        self,
        helper: "OpenCTIConnectorHelper",
        tlp_marking: "TLPMarking",
    ):
        """Initialize the converter."""
        self._helper = helper
        self._author = Author(
            name="Tenable Security Center",
            description="Tenable Security Center is a vulnerability management solution that provides real-time visibility into"
            " an organization's security posture. It aggregates data from various Tenable products to identify "
            "vulnerabilities, misconfigurations, and compliance issues, enabling users to prioritize risks and "
            "track remediation efforts.",
            contact_information="https://www.tenable.com/about-tenable/contact-tenable",
            x_opencti_organization_type="vendor",
            confidence=None,
            x_opencti_aliases=None,
            x_opencti_reliability=None,
        )
        self._object_marking_refs: list[str] = [tlp_marking["id"]]

    def _system_from_asset(
        self, asset: "AssetPort"
    ) -> tuple[System, list["Observable"]]:
        system = System(
            name=asset.name,
            author=self._author,
            created=asset.created_time,
            modified=asset.modified_time,
            description=None,
            object_marking_refs=self._object_marking_refs,
        )

        # holder for System Observables
        observables_holder: list[Optional["Observable"]] = []

        operating_systems = [
            OperatingSystem(
                name=operating_system_name,
                author=self._author,
                object_marking_refs=self._object_marking_refs,
            )
            for operating_system_name in asset.operating_systems or []
        ]

        observables_holder.extend(operating_systems)

        mac_address = (
            MACAddress(
                value=asset.mac_address,
                author=self._author,
                object_marking_refs=self._object_marking_refs,
            )
            if asset.mac_address
            else None
        )
        observables_holder.append(mac_address)

        ip_address = IPAddress(
            value=asset.ip_address,
            version=(
                "v4" if ipaddress.ip_address(asset.ip_address).version == 4 else "v6"
            ),
            author=self._author,
            object_marking_refs=self._object_marking_refs,
            resolves_to_mac_addresses=[mac_address] if mac_address else None,
        )

        observables_holder.append(ip_address)

        domain_name = (
            DomainName(
                value=asset.name,
                resolves_to_ips=[ip_address],
                resolves_to_domain_names=None,
                author=self._author,
                object_marking_refs=self._object_marking_refs,
            )
            if validators.domain(asset.name)
            else None
        )
        observables_holder.append(domain_name)

        observables: list[Observable] = [
            obs for obs in observables_holder if obs is not None
        ]  # filter None values

        return system, observables

    def _vulnerabilities_from_cve(
        self, cve: "CVEPort", severity_fallback: Optional[str] = None
    ) -> tuple[Vulnerability, list[Software]]:

        cvss = (
            Vulnerability.parse_cvss3_vector(cve.cvss_v3_vector)
            if cve.cvss_v3_vector
            else None
        )
        vulnerability = Vulnerability(
            author=self._author,
            created=cve.publication_datetime,
            modified=cve.last_modified_datetime,
            name=cve.name,
            description=cve.description,
            object_marking_refs=self._object_marking_refs,
            cvss3_score=cve.cvss_v3_score,
            cvss3_severity=(
                Vulnerability.cvss3_severity_from_score(cve.cvss_v3_score)  # type: ignore[arg-type]
                if cve.cvss_v3_score
                else severity_fallback
            ),
            cvss3_attack_vector=cvss.metrics["AV"] if cvss else None,
            cvss3_integrity_impact=cvss.metrics["I"] if cvss else None,
            cvss3_availability_impact=cvss.metrics["A"] if cvss else None,
            cvss3_confidentiality_impact=cvss.metrics["C"] if cvss else None,
            confidence=None,
        )
        software_s = []
        for cpe_uri in cve.cpes if cve.cpes else []:
            details = Software.parse_cpe_uri(cpe_uri)
            software_s.append(
                Software(
                    name=f"{details['product']}-{details['part']}",
                    vendor=details["vendor"],
                    cpe=cpe_uri,
                    author=self._author,
                    object_marking_refs=self._object_marking_refs,
                )
            )
        return (vulnerability, software_s)

    def _vulnerability_from_finding(
        self, finding: "FindingPort"
    ) -> tuple[Vulnerability, list[Software]]:
        cvss = (
            Vulnerability.parse_cvss3_vector(finding.cvss_v3_vector)
            if finding.cvss_v3_vector
            else None
        )
        vulnerability = Vulnerability(
            author=self._author,
            created=finding.first_seen,
            modified=finding.last_seen,
            name=finding.plugin_name,
            description=finding.description,
            object_marking_refs=self._object_marking_refs,
            cvss3_score=finding.cvss_v3_base_score,
            cvss3_severity=(
                Vulnerability.cvss3_severity_from_score(finding.cvss_v3_base_score)  # type: ignore[arg-type]
                if finding.cvss_v3_base_score
                else finding.tenable_severity
            ),
            cvss3_attack_vector=cvss.metrics["AV"] if cvss else None,
            cvss3_integrity_impact=cvss.metrics["I"] if cvss else None,
            cvss3_availability_impact=cvss.metrics["A"] if cvss else None,
            cvss3_confidentiality_impact=cvss.metrics["C"] if cvss else None,
            confidence=None,
        )

        software_s = []
        for cpe_uri in finding.cpes if finding.cpes else []:
            details = Software.parse_cpe_uri(cpe_uri)
            software_s.append(
                Software(
                    name=details["product"],
                    vendor=details["vendor"],
                    cpe=cpe_uri,
                    author=self._author,
                    object_marking_refs=self._object_marking_refs,
                )
            )

        return vulnerability, software_s

    def process_assets_chunk(
        self,
        assets_chunk: "AssetsChunkPort",
        process_systems_without_vulnerabilities: bool,
    ) -> dict[str, "_STIXBase21"]:
        """Process a chunk of assets and convert them into STIX 2.1 objects.

        Args:
            assets_chunk (AssetsChunkPort): The chunk of assets to process.
            process_systems_without_vulnerabilities (bool): A flag indicating whether to process systems without vulnerabilities.

        Returns:
            dict[str, "_STIXBase21"]: A dictionary containing the STIX 2.1 objects and their stix standard id as keys.

        """
        bundle: list["BaseEntity"] = [self._author]  # results holder
        findings: list["FindingPort"] = []
        for asset in assets_chunk.assets:
            self._helper.connector_logger.info(f"Processing asset {asset.name}")
            if not process_systems_without_vulnerabilities:
                findings = list(
                    asset.findings
                )  # Note: this breaks the possible lazy execution
                if len(findings) == 0:
                    self._helper.connector_logger.info(
                        f"Skipping system {asset.name} because it has no vulnerabilities"
                    )
                    continue

            external_references = [
                ExternalReference(
                    source_name="Tenable Security Center",
                    description="Tenable Security Center Asset Page",
                    url=f"https://sc.tenalab.online/#hosts/view/{asset.uuid}",
                )
            ]

            system, observables = self._system_from_asset(asset)
            bundle.append(system)
            bundle.extend(observables)
            relationships = [
                RelatedToRelationship(
                    author=self._author,
                    created=None,
                    modified=None,
                    description=None,
                    source_ref=system,
                    target_ref=obs,
                    start_time=None,
                    stop_time=None,
                    confidence=None,
                    object_marking_refs=self._object_marking_refs,
                    external_references=None,
                )
                for obs in observables
            ]
            bundle.extend(relationships)

            for finding in findings if len(findings) > 0 else asset.findings:
                if finding.cves:
                    vulnerabilities = [
                        self._vulnerabilities_from_cve(
                            cve, severity_fallback=finding.tenable_severity
                        )
                        for cve in finding.cves
                    ]

                else:
                    vulnerabilities = [self._vulnerability_from_finding(finding)]

                for vulnerability, software_s in vulnerabilities:

                    bundle.append(vulnerability)
                    bundle.extend(software_s)

                    system_has_vulnerability_rel = HasRelationship(
                        author=self._author,
                        created=vulnerability.created,
                        modified=vulnerability.modified,
                        description=None,
                        source_ref=system,
                        target_ref=vulnerability,
                        start_time=vulnerability.created,
                        stop_time=(
                            finding.last_seen
                            if not finding.has_been_mitigated
                            else None
                        ),
                        confidence=None,
                        object_marking_refs=self._object_marking_refs,
                        external_references=external_references,
                    )

                    bundle.append(system_has_vulnerability_rel)

                    software_has_vulnerability_rels = [
                        HasRelationship(
                            author=self._author,
                            created=finding.plugin_pub_date,
                            modified=finding.plugin_mod_date,
                            description=None,
                            source_ref=software,
                            target_ref=vulnerability,
                            start_time=finding.plugin_pub_date,
                            stop_time=None,
                            confidence=None,
                            object_marking_refs=self._object_marking_refs,
                            external_references=None,
                        )
                        for software in software_s
                    ]

                    bundle.extend(software_has_vulnerability_rels)

        return {obj.id: obj.to_stix2_object() for obj in bundle}
