# isort: skip_file # Skipping this file to prevent isort from removing type ignore comments for untyped imports
"""Provides the use case classes for the Tenable Security Center integration."""

import ipaddress
from typing import TYPE_CHECKING, Iterable, Optional

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
    import datetime

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
    from tenable_security_center.utils import AppLogger


class ConverterToStix:
    """Provides methods for converting various types of input data into STIX 2.1 objects."""

    def __init__(
        self,
        logger: "AppLogger",
        tlp_marking: "TLPMarking",
    ):
        """Initialize the converter."""
        self.logger = logger
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

    def _make_targeted_softwares(
        self, cpe_uris: Optional[Iterable[str]]
    ) -> list[Software]:
        """Parse CPE URIs into a list of Software objects, skipping p-cpe URIs."""
        software_s = []
        for cpe_uri in cpe_uris or []:
            if cpe_uri.startswith("p-cpe"):
                self.logger.debug("skipping p-cpe uri", meta={"cpe_uri": cpe_uri})
                continue
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
        return software_s

    def _make_vulnerability(
        self,
        name: str,
        description: Optional[str],
        created: Optional["datetime.datetime"],
        modified: Optional["datetime.datetime"],
        cvss_vector: Optional[str],
        cvss_score: Optional[float],
        severity_fallback: Optional[str],
    ) -> Vulnerability:
        """Build a Vulnerability object from common fields."""
        cvss = Vulnerability.parse_cvss3_vector(cvss_vector) if cvss_vector else None
        return Vulnerability(
            author=self._author,
            created=created,
            modified=modified,
            name=name,
            description=description,
            object_marking_refs=self._object_marking_refs,
            cvss3_score=cvss_score,
            cvss3_severity=(
                Vulnerability.cvss3_severity_from_score(cvss_score)  # type: ignore[arg-type]
                if cvss_score
                else severity_fallback
            ),
            cvss3_attack_vector=cvss.metrics["AV"] if cvss else None,
            cvss3_integrity_impact=cvss.metrics["I"] if cvss else None,
            cvss3_availability_impact=cvss.metrics["A"] if cvss else None,
            cvss3_confidentiality_impact=cvss.metrics["C"] if cvss else None,
            confidence=None,
        )

    def _vulnerabilities_from_cve(
        self, cve: "CVEPort", severity_fallback: Optional[str] = None
    ) -> tuple[Vulnerability, list[Software]]:

        vulnerability = self._make_vulnerability(
            name=cve.name,
            description=cve.description,
            created=cve.publication_datetime,
            modified=cve.last_modified_datetime,
            cvss_vector=cve.cvss_v3_vector,
            cvss_score=cve.cvss_v3_score,
            severity_fallback=severity_fallback,
        )

        software_s = self._make_targeted_softwares(
            cpe_uris=cve.cpes if cve.cpes else []
        )
        return (vulnerability, software_s)

    def _vulnerability_from_finding(
        self, finding: "FindingPort"
    ) -> tuple[Vulnerability, list[Software]]:
        vulnerability = self._make_vulnerability(
            name=finding.plugin_name,
            description=finding.description,
            created=finding.plugin_pub_date,
            modified=finding.plugin_mod_date,
            cvss_vector=finding.cvss_v3_vector,
            cvss_score=finding.cvss_v3_base_score,
            severity_fallback=finding.tenable_severity,
        )

        software_s = self._make_targeted_softwares(cpe_uris=finding.cpes)
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
        bundle: list["BaseEntity"] = []  # results holder
        findings: list["FindingPort"] = []
        for asset in assets_chunk.assets:
            self.logger.info(f"Processing asset {asset.name}")
            if not process_systems_without_vulnerabilities:
                findings = list(
                    asset.findings
                )  # Note: this breaks the possible lazy execution
                if len(findings) == 0:
                    self.logger.info(
                        f"Skipping system {asset.name} because it has no vulnerabilities"
                    )
                    continue
                else:
                    self.logger.info(
                        f"Processing system {asset.name} with {len(findings)} vulnerabilities"
                    )

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
                            finding.last_seen if finding.has_been_mitigated else None
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

        if len(bundle) == 0:
            return {}

        bundle.append(self._author)
        return {obj.id: obj.to_stix2_object() for obj in bundle}
