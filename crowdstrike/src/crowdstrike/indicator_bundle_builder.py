# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator bundle builder module."""

import logging
from typing import List, Optional, Mapping

from crowdstrike_client.api.models import Indicator
from crowdstrike_client.api.models.report import Report
from pycti.utils.constants import CustomProperties
from pydantic import BaseModel
from stix2 import (
    Indicator as STIXIndicator,
    Bundle,
    Identity,
    MarkingDefinition,
    IntrusionSet,
    KillChainPhase,
    Report as STIXReport,
    Malware,
    Relationship,
    Vulnerability,
    ObservationExpression,
    ObjectPath,
    EqualityComparisonExpression,
    StringConstant,
)
from stix2.core import STIXDomainObject

from crowdstrike.utils import (
    create_intrusion_set,
    create_kill_chain_phase,
    create_malware,
    create_uses_relationships,
    create_sector,
    create_targets_relationships,
    create_external_reference,
    create_vulnerability,
    create_indicates_relationships,
    create_object_refs,
    create_tags,
    create_stix2_report_from_report,
)


logger = logging.getLogger(__name__)


class IndicatorReport(BaseModel):
    """Indicator report model."""

    report: Report
    files: List[Mapping[str, str]] = []


class IndicatorBundleBuilder:
    """Indicator bundle builder."""

    _OPENCTI_TYPE_FILE_MD5 = "file-md5"
    _OPENCTI_TYPE_FILE_SHA1 = "file-sha1"
    _OPENCTI_TYPE_FILE_SHA256 = "file-sha256"
    _OPENCTI_TYPE_FILE_NAME = "file-name"
    _OPENCTI_TYPE_FILE_PATH = "file-path"
    _OPENCTI_TYPE_EMAIL_ADDRESS = "email-address"
    _OPENCTI_TYPE_EMAIL_SUBJECT = "email-subject"
    _OPENCTI_TYPE_URL = "url"
    _OPENCTI_TYPE_DOMAIN = "domain"
    _OPENCTI_TYPE_IPV4_ADDR = "ipv4-addr"
    _OPENCTI_TYPE_MUTEX = "mutex"
    _OPENCTI_TYPE_REGISTRY_KEY = "registry-key"
    _OPENCTI_TYPE_WINDOWS_SERVICE_NAME = "windows-service-name"
    _OPENCTI_TYPE_X509_CERTIFICATE_SERIAL_NUMBER = "x509-certificate-serial-number"
    _OPENCTI_TYPE_X509_CERTIFICATE_ISSUER = "x509-certificate-issuer"

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
        # 'autonomous-system': {
        #     'type': 'autonomous-system',
        #     'path': ['number'],
        #     'transform': {
        #         'operation': 'remove_string',
        #         'value': 'AS'}
        # },
        # 'mac-addr': {'type': 'mac-addr', 'path': ['value']},
        _OPENCTI_TYPE_DOMAIN: {"type": "domain-name", "path": ["value"]},
        _OPENCTI_TYPE_IPV4_ADDR: {"type": "ipv4-addr", "path": ["value"]},
        # 'ipv6-addr': {'type': 'ipv6-addr', 'path': ['value']},
        _OPENCTI_TYPE_URL: {"type": "url", "path": ["value"]},
        _OPENCTI_TYPE_EMAIL_ADDRESS: {"type": "email-addr", "path": ["value"]},
        _OPENCTI_TYPE_EMAIL_SUBJECT: {"type": "email-message", "path": ["subject"]},
        _OPENCTI_TYPE_MUTEX: {"type": "mutex", "path": ["name"]},
        _OPENCTI_TYPE_FILE_NAME: {"type": "file", "path": ["name"]},
        _OPENCTI_TYPE_FILE_PATH: {"type": "file", "path": ["name"]},
        _OPENCTI_TYPE_FILE_MD5: {"type": "file", "path": ["hashes", "MD5"]},
        _OPENCTI_TYPE_FILE_SHA1: {"type": "file", "path": ["hashes", "SHA1"]},
        _OPENCTI_TYPE_FILE_SHA256: {"type": "file", "path": ["hashes", "SHA256"]},
        # 'directory': {'type': 'directory', 'path': ['path']},
        _OPENCTI_TYPE_REGISTRY_KEY: {"type": "windows-registry-key", "path": ["key"]},
        # 'registry-key-value': {'type': 'windows-registry-value-type', 'path': ['data']},
        # 'pdb-path': {'type': 'file', 'path': ['name']},
        _OPENCTI_TYPE_WINDOWS_SERVICE_NAME: {
            "type": "windows-service-ext",
            "path": ["service_name"],
        },
        # 'windows-service-display-name': {
        #     'type': 'windows-service-ext',
        #     'path': ['display_name']
        # },
        _OPENCTI_TYPE_X509_CERTIFICATE_ISSUER: {
            "type": "x509-certificate",
            "path": ["issuer"],
        },
        _OPENCTI_TYPE_X509_CERTIFICATE_SERIAL_NUMBER: {
            "type": "x509-certificate",
            "path": ["serial_number"],
        },
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
        indicator_reports: List[IndicatorReport],
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
    def _get_opencti_type(cls, indicator_type: str):
        opencti_type = cls._INDICATOR_TYPE_TO_OPENCTI_TYPE.get(indicator_type)
        if opencti_type is None:
            raise TypeError(f"Indicator type not allowed: '{indicator_type}'")
        return opencti_type

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        intrusion_sets = []
        for actor_name in self.indicator.actors:
            name = actor_name
            aliases = []
            primary_motivation = None
            secondary_motivations = []
            external_references = []

            intrusion_set = create_intrusion_set(
                name,
                aliases,
                self.author,
                primary_motivation,
                secondary_motivations,
                external_references,
                self.object_marking_refs,
            )

            intrusion_sets.append(intrusion_set)
        return intrusion_sets

    def _create_kill_chain_phases(self) -> List[KillChainPhase]:
        kill_chain_phases = []
        for kill_chain in self.indicator.kill_chains:
            kill_chain_phase = create_kill_chain_phase(self.source_name, kill_chain)
            kill_chain_phases.append(kill_chain_phase)
        return kill_chain_phases

    def _create_malwares(
        self, kill_chain_phases: List[KillChainPhase]
    ) -> List[Malware]:
        malwares = []

        indicator_malware_families = self.indicator.malware_families
        if indicator_malware_families:
            malware_external_references = []

            malware_name = indicator_malware_families[0]
            malware_aliases = indicator_malware_families[1:]

            malware = create_malware(
                malware_name,
                malware_aliases,
                self.author,
                kill_chain_phases,
                malware_external_references,
                self.object_marking_refs,
            )

            malwares.append(malware)

        return malwares

    def _create_uses_relationships(
        self, sources: List[STIXDomainObject], targets: List[STIXDomainObject]
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
        self, sources: List[STIXDomainObject], targets: List[STIXDomainObject]
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

    def _create_indicator_pattern(
        self, indicator_type: str, indicator_value: str
    ) -> ObservationExpression:
        stix2_typing = self._OPENCTI_TO_STIX2[indicator_type]
        lhs = ObjectPath(stix2_typing["type"], stix2_typing["path"])
        operand = str(
            EqualityComparisonExpression(lhs, StringConstant(indicator_value))
        )
        observation_expression = ObservationExpression(operand)
        return observation_expression

    def _create_indicator(
        self, kill_chain_phases: List[KillChainPhase]
    ) -> STIXIndicator:
        stix_indicator = STIXIndicator(
            created_by_ref=self.author,
            name=self.indicator.indicator,
            pattern=str(
                self._create_indicator_pattern(
                    self.opencti_type, self.indicator.indicator
                )
            ),
            valid_from=self.indicator.published_date,
            kill_chain_phases=kill_chain_phases,
            labels=["malicious-activity"],
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                CustomProperties.OBSERVABLE_TYPE: self.opencti_type,
                CustomProperties.OBSERVABLE_VALUE: self.indicator.indicator,
                CustomProperties.PATTERN_TYPE: self._PATTERN_TYPE_STIX,
            },
        )
        return stix_indicator

    def _create_indicators(
        self, kill_chain_phases: List[KillChainPhase]
    ) -> List[STIXIndicator]:
        return [self._create_indicator(kill_chain_phases)]

    def _create_indicates_relationships(
        self, sources: List[STIXDomainObject], targets: List[STIXDomainObject]
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
        object_refs: List[STIXDomainObject],
        object_marking_refs: List[MarkingDefinition],
        files: List[Mapping[str, str]],
    ) -> STIXReport:
        external_references = []

        # Create external references.
        external_reference = create_external_reference(
            self.source_name, str(report.id), report.url
        )
        external_references.append(external_reference)

        # Create tags.
        tags = create_tags(report.tags, self.source_name)

        return create_stix2_report_from_report(
            report,
            author,
            object_refs,
            external_references,
            object_marking_refs,
            self.indicator_report_status,
            self.indicator_report_type,
            self.confidence_level,
            tags,
            files,
        )

    def _create_reports(self, object_refs: List[STIXDomainObject]) -> List[STIXReport]:
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
