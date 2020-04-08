# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator bundle builder module."""

import logging
from typing import List, Mapping, Optional

from crowdstrike_client.api.models import Indicator
from crowdstrike_client.api.models.report import Report

from pycti.utils.constants import ObservableTypes

from stix2 import (
    Bundle,
    ExternalReference,
    Identity,
    Indicator as STIXIndicator,
    IntrusionSet,
    KillChainPhase,
    Malware,
    MarkingDefinition,
    Relationship,
    Report as STIXReport,
    Vulnerability,
)
from stix2.v20 import _DomainObject

from crowdstrike.report_fetcher import FetchedReport
from crowdstrike.utils import (
    create_equality_observation_expression_str,
    create_external_reference,
    create_indicates_relationships,
    create_indicator,
    create_intrusion_sets_from_names,
    create_kill_chain_phase,
    create_malware,
    create_object_path,
    create_object_refs,
    create_sector,
    create_stix2_report_from_report,
    create_targets_relationships,
    create_uses_relationships,
    create_vulnerability,
)

logger = logging.getLogger(__name__)


class IndicatorBundleBuilder:
    """Indicator bundle builder."""

    _OPENCTI_TYPE_FILE_MD5 = ObservableTypes.FILE_HASH_MD5
    _OPENCTI_TYPE_FILE_SHA1 = ObservableTypes.FILE_HASH_SHA1
    _OPENCTI_TYPE_FILE_SHA256 = ObservableTypes.FILE_HASH_SHA256
    _OPENCTI_TYPE_FILE_NAME = ObservableTypes.FILE_NAME
    _OPENCTI_TYPE_FILE_PATH = ObservableTypes.FILE_PATH
    _OPENCTI_TYPE_EMAIL_ADDRESS = ObservableTypes.EMAIL_ADDR
    _OPENCTI_TYPE_EMAIL_SUBJECT = ObservableTypes.EMAIL_SUBJECT
    _OPENCTI_TYPE_URL = ObservableTypes.URL
    _OPENCTI_TYPE_DOMAIN = ObservableTypes.DOMAIN
    _OPENCTI_TYPE_IPV4_ADDR = ObservableTypes.IPV4_ADDR
    _OPENCTI_TYPE_MUTEX = ObservableTypes.MUTEX
    _OPENCTI_TYPE_REGISTRY_KEY = ObservableTypes.REGISTRY_KEY
    _OPENCTI_TYPE_WINDOWS_SERVICE_NAME = ObservableTypes.WIN_SERVICE_NAME
    _OPENCTI_TYPE_X509_CERTIFICATE_SERIAL_NUMBER = ObservableTypes.X509_CERT_SN
    _OPENCTI_TYPE_X509_CERTIFICATE_ISSUER = ObservableTypes.X509_CERT_ISSUER

    _INDICATOR_TYPE_TO_OPENCTI_TYPE = {
        # "binary_string": "",  # NOT SUPPORTED
        # "compile_time": "",  # NOT SUPPORTED
        # "device_name": "",  # NOT SUPPORTED
        "domain": _OPENCTI_TYPE_DOMAIN,
        "email_address": _OPENCTI_TYPE_EMAIL_ADDRESS,
        "email_subject": _OPENCTI_TYPE_EMAIL_SUBJECT,
        # "event_name": "",  # NOT SUPPORTED
        # "file_mapping": "",  # NOT SUPPORTED
        "file_name": _OPENCTI_TYPE_FILE_NAME,
        "file_path": _OPENCTI_TYPE_FILE_PATH,
        # "hash_ion": "",  # NOT SUPPORTED
        "hash_md5": _OPENCTI_TYPE_FILE_MD5,
        "hash_sha1": _OPENCTI_TYPE_FILE_SHA1,
        "hash_sha256": _OPENCTI_TYPE_FILE_SHA256,
        "ip_address": _OPENCTI_TYPE_IPV4_ADDR,
        # "ip_address_block": "",  # NOT SUPPORTED
        "mutex_name": _OPENCTI_TYPE_MUTEX,
        # "password": "",  # NOT SUPPORTED
        # "persona_name": "",  # NOT SUPPORTED
        # "phone_number": "",  # NOT SUPPORTED
        # "port": "",  # NOT SUPPORTED
        "registry": _OPENCTI_TYPE_REGISTRY_KEY,
        "semaphore_name": _OPENCTI_TYPE_MUTEX,
        "service_name": _OPENCTI_TYPE_WINDOWS_SERVICE_NAME,
        "url": _OPENCTI_TYPE_URL,
        # "user_agent": "",  # NOT SUPPORTED
        # "username": "",  # NOT SUPPORTED
        "x509_serial": _OPENCTI_TYPE_X509_CERTIFICATE_SERIAL_NUMBER,
        "x509_subject": _OPENCTI_TYPE_X509_CERTIFICATE_ISSUER,
    }

    _OPENCTI_TO_STIX2 = {
        _OPENCTI_TYPE_DOMAIN: create_object_path("domain-name", ["value"]),
        _OPENCTI_TYPE_IPV4_ADDR: create_object_path("ipv4-addr", ["value"]),
        _OPENCTI_TYPE_URL: create_object_path("url", ["value"]),
        _OPENCTI_TYPE_EMAIL_ADDRESS: create_object_path("email-addr", ["value"]),
        _OPENCTI_TYPE_EMAIL_SUBJECT: create_object_path("email-message", ["subject"]),
        _OPENCTI_TYPE_MUTEX: create_object_path("mutex", ["name"]),
        _OPENCTI_TYPE_FILE_NAME: create_object_path("file", ["name"]),
        _OPENCTI_TYPE_FILE_PATH: create_object_path("file", ["name"]),
        _OPENCTI_TYPE_FILE_MD5: create_object_path("file", ["hashes", "MD5"]),
        _OPENCTI_TYPE_FILE_SHA1: create_object_path("file", ["hashes", "SHA1"]),
        _OPENCTI_TYPE_FILE_SHA256: create_object_path("file", ["hashes", "SHA256"]),
        _OPENCTI_TYPE_REGISTRY_KEY: create_object_path("windows-registry-key", ["key"]),
        _OPENCTI_TYPE_WINDOWS_SERVICE_NAME: create_object_path(
            "windows-service-ext", ["service_name"]
        ),
        _OPENCTI_TYPE_X509_CERTIFICATE_ISSUER: create_object_path(
            "x509-certificate", ["issuer"]
        ),
        _OPENCTI_TYPE_X509_CERTIFICATE_SERIAL_NUMBER: create_object_path(
            "x509-certificate", ["serial_number"]
        ),
    }

    _PATTERN_TYPE_STIX = "stix"

    def __init__(
        self,
        indicator: Indicator,
        author: Identity,
        source_name: str,
        object_marking_refs: List[MarkingDefinition],
        confidence_level: int,
        indicator_report_status: int,
        indicator_report_type: str,
        indicator_reports: List[FetchedReport],
    ) -> None:
        """Initialize indicator bundle builder."""
        self.indicator = indicator
        self.author = author
        self.source_name = source_name
        self.object_marking_refs = object_marking_refs
        self.confidence_level = confidence_level
        self.indicator_reports = indicator_reports
        self.indicator_report_status = indicator_report_status
        self.indicator_report_type = indicator_report_type

        self.opencti_type = self._get_opencti_type(indicator.type)

        first_seen = self.indicator.published_date
        last_seen = self.indicator.last_updated

        if first_seen > last_seen:
            logger.warning(
                "First seen is greater than last seen for indicator: %s",
                self.indicator.indicator,
            )
            first_seen, last_seen = last_seen, first_seen

        self.first_seen = first_seen
        self.last_seen = last_seen

    @classmethod
    def _get_opencti_type(cls, indicator_type: str) -> ObservableTypes:
        opencti_type = cls._INDICATOR_TYPE_TO_OPENCTI_TYPE.get(indicator_type)
        if opencti_type is None:
            raise TypeError(f"Indicator type not allowed: '{indicator_type}'")
        return opencti_type

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        external_references: List[ExternalReference] = []
        return create_intrusion_sets_from_names(
            self.indicator.actors,
            self.author,
            external_references,
            self.object_marking_refs,
        )

    def _create_kill_chain_phases(self) -> List[KillChainPhase]:
        kill_chain_phases = []
        for kill_chain in self.indicator.kill_chains:
            kill_chain_phase = create_kill_chain_phase(self.source_name, kill_chain)
            kill_chain_phases.append(kill_chain_phase)
        return kill_chain_phases

    def _create_malwares(
        self, kill_chain_phases: List[KillChainPhase]
    ) -> List[Malware]:
        indicator_malware_families = self.indicator.malware_families
        if not indicator_malware_families:
            return []

        name = indicator_malware_families[0]
        aliases = indicator_malware_families[1:]
        external_references: List[ExternalReference] = []

        malware = create_malware(
            name,
            aliases,
            self.author,
            kill_chain_phases,
            external_references,
            self.object_marking_refs,
        )

        return [malware]

    def _create_uses_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_uses_relationships(
            self.author,
            sources,
            targets,
            self.object_marking_refs,
            self.first_seen,
            self.last_seen,
            self.confidence_level,
        )

    def _create_targeted_sectors(self) -> List[Identity]:
        target_sectors = []
        for target in self.indicator.targets:
            target_sector = create_sector(target, self.author)
            target_sectors.append(target_sector)
        return target_sectors

    def _create_targets_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_targets_relationships(
            self.author,
            sources,
            targets,
            self.object_marking_refs,
            self.first_seen,
            self.last_seen,
            self.confidence_level,
        )

    @staticmethod
    def _create_vulnerability(
        vulnerability_name: str,
        author: Identity,
        object_marking_refs: List[MarkingDefinition],
    ):
        external_references = []
        if vulnerability_name.startswith("CVE-"):
            external_reference = create_external_reference(
                "NIST NVD",
                vulnerability_name,
                f"https://nvd.nist.gov/vuln/detail/{vulnerability_name}",
            )
            external_references.append(external_reference)
        return create_vulnerability(
            vulnerability_name, author, external_references, object_marking_refs
        )

    def _create_vulnerabilities(self) -> List[Vulnerability]:
        vulnerabilities = []
        for vulnerability_name in self.indicator.vulnerabilities:
            vulnerability = self._create_vulnerability(
                vulnerability_name, self.author, self.object_marking_refs
            )
            vulnerabilities.append(vulnerability)
        return vulnerabilities

    def _create_indicator(
        self, kill_chain_phases: List[KillChainPhase]
    ) -> STIXIndicator:
        indicator = self.indicator

        name = indicator.indicator
        description = ""
        valid_from = indicator.published_date
        observable_type = str(self.opencti_type.value)
        observable_value = indicator.indicator
        pattern_type = self._PATTERN_TYPE_STIX
        pattern_value = create_equality_observation_expression_str(
            self._OPENCTI_TO_STIX2[self.opencti_type], self.indicator.indicator
        )
        indicator_pattern = pattern_value

        return create_indicator(
            name,
            description,
            self.author,
            valid_from,
            kill_chain_phases,
            observable_type,
            observable_value,
            pattern_type,
            pattern_value,
            indicator_pattern,
            self.object_marking_refs,
        )

    def _create_indicators(
        self, kill_chain_phases: List[KillChainPhase]
    ) -> List[STIXIndicator]:
        return [self._create_indicator(kill_chain_phases)]

    def _create_indicates_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_indicates_relationships(
            self.author,
            sources,
            targets,
            self.object_marking_refs,
            self.first_seen,
            self.last_seen,
            self.confidence_level,
        )

    def _create_report(
        self,
        report: Report,
        author: Identity,
        object_refs: List[_DomainObject],
        object_marking_refs: List[MarkingDefinition],
        files: List[Mapping[str, str]],
    ) -> STIXReport:
        return create_stix2_report_from_report(
            report,
            author,
            self.source_name,
            object_refs,
            object_marking_refs,
            self.indicator_report_status,
            self.indicator_report_type,
            self.confidence_level,
            files,
        )

    def _create_reports(self, object_refs: List[_DomainObject]) -> List[STIXReport]:
        reports = []
        for indicator_report in self.indicator_reports:
            stix2_report = self._create_report(
                indicator_report.report,
                self.author,
                object_refs,
                self.object_marking_refs,
                indicator_report.files,
            )
            reports.append(stix2_report)
        return reports

    def build(self) -> Optional[Bundle]:
        """Build indicator bundle."""
        # Create bundle with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_marking_refs)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create kill chain phases.
        kill_chain_phases = self._create_kill_chain_phases()

        # Create malwares and add to bundle.
        malwares = self._create_malwares(kill_chain_phases)
        bundle_objects.extend(malwares)

        # Intrusion sets use malwares, add to bundle.
        intrusion_sets_use_malwares = self._create_uses_relationships(
            intrusion_sets, malwares
        )
        bundle_objects.extend(intrusion_sets_use_malwares)

        # Create target sectors and add to bundle.
        target_sectors = self._create_targeted_sectors()
        bundle_objects.extend(target_sectors)

        # Intrusion sets target sectors, add to bundle.
        intrusion_sets_target_sectors = self._create_targets_relationships(
            intrusion_sets, target_sectors
        )
        bundle_objects.extend(intrusion_sets_target_sectors)

        # Malwares target sectors, add to bundle.
        malwares_target_sectors = self._create_targets_relationships(
            malwares, target_sectors
        )
        bundle_objects.extend(malwares_target_sectors)

        # Create vulnerabilities and add to bundle.
        vulnerabilities = self._create_vulnerabilities()
        bundle_objects.extend(vulnerabilities)

        # Intrusion sets target vulnerabilities, add to bundle.
        intrusion_sets_target_vulnerabilities = self._create_targets_relationships(
            intrusion_sets, vulnerabilities
        )
        bundle_objects.extend(intrusion_sets_target_vulnerabilities)

        # Malwares target vulnerabilities, add to bundle.
        malwares_target_vulnerabilities = self._create_targets_relationships(
            malwares, vulnerabilities
        )
        bundle_objects.extend(malwares_target_vulnerabilities)

        # Create an indicators and add to bundle.
        indicators = self._create_indicators(kill_chain_phases)
        bundle_objects.extend(indicators)

        # Indicator(s) indicate entities, add to bundle.
        entities = intrusion_sets + malwares

        indicator_indicates_entities = self._create_indicates_relationships(
            indicators, entities
        )
        bundle_objects.extend(indicator_indicates_entities)

        # Create object references for the report.
        object_refs = create_object_refs(
            intrusion_sets,
            malwares,
            intrusion_sets_use_malwares,
            target_sectors,
            intrusion_sets_target_sectors,
            malwares_target_sectors,
            vulnerabilities,
            intrusion_sets_target_vulnerabilities,
            malwares_target_vulnerabilities,
            indicators,
            indicator_indicates_entities,
        )

        # Create reports and add to bundle.
        reports = self._create_reports(object_refs)
        bundle_objects.extend(reports)

        return Bundle(objects=bundle_objects)
