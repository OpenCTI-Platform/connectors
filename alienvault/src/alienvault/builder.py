# -*- coding: utf-8 -*-
"""OpenCTI AlienVault builder module."""

import logging
from datetime import datetime
from typing import List, Mapping

from pycti.utils.constants import CustomProperties, ObservableTypes

from stix2 import (
    AttackPattern,
    Bundle,
    ExternalReference,
    Identity,
    Indicator,
    IntrusionSet,
    Malware,
    MarkingDefinition,
    Relationship,
    Report,
    Vulnerability,
)
from stix2.core import STIXDomainObject

from alienvault.models import Pulse, PulseIndicator
from alienvault.utils import (
    create_attack_pattern,
    create_attack_pattern_external_reference,
    create_country,
    create_equality_observation_expression_str,
    create_external_reference,
    create_indicates_relationships,
    create_indicator,
    create_intrusion_set,
    create_malware,
    create_object_path,
    create_object_refs,
    create_sector,
    create_tag,
    create_targets_relationships,
    create_uses_relationships,
    create_vulnerability,
    create_vulnerability_external_reference,
)


class PulseBundleBuilder:
    """Pulse bundle builder."""

    _OPENCTI_TYPE_FILE_MD5 = ObservableTypes.FILE_HASH_MD5
    _OPENCTI_TYPE_FILE_SHA1 = ObservableTypes.FILE_HASH_SHA1
    _OPENCTI_TYPE_FILE_SHA256 = ObservableTypes.FILE_HASH_SHA256
    _OPENCTI_TYPE_FILE_PATH = ObservableTypes.FILE_PATH
    _OPENCTI_TYPE_EMAIL_ADDRESS = ObservableTypes.EMAIL_ADDR
    _OPENCTI_TYPE_URL = ObservableTypes.URL
    _OPENCTI_TYPE_DOMAIN = ObservableTypes.DOMAIN
    _OPENCTI_TYPE_IPV4_ADDR = ObservableTypes.IPV4_ADDR
    _OPENCTI_TYPE_IPV6_ADDR = ObservableTypes.IPV6_ADDR
    _OPENCTI_TYPE_MUTEX = ObservableTypes.MUTEX

    _INDICATOR_TYPE_TO_OPENCTI_TYPE = {
        "CIDR": _OPENCTI_TYPE_IPV4_ADDR,
        "domain": _OPENCTI_TYPE_DOMAIN,
        "email": _OPENCTI_TYPE_EMAIL_ADDRESS,
        "FileHash-MD5": _OPENCTI_TYPE_FILE_MD5,
        "FileHash-SHA1": _OPENCTI_TYPE_FILE_SHA1,
        "FileHash-SHA256": _OPENCTI_TYPE_FILE_SHA256,
        "FilePath": _OPENCTI_TYPE_FILE_PATH,
        "hostname": _OPENCTI_TYPE_DOMAIN,
        "IPv4": _OPENCTI_TYPE_IPV4_ADDR,
        "IPv6": _OPENCTI_TYPE_IPV6_ADDR,
        "Mutex": _OPENCTI_TYPE_MUTEX,
        "URI": _OPENCTI_TYPE_URL,
        "URL": _OPENCTI_TYPE_URL,
    }

    # Following indicator types require special handling.
    _INDICATOR_TYPE_YARA = "YARA"
    _INDICATOR_TYPE_CVE = "CVE"

    _INDICATOR_TYPES_WITH_SPECIAL_HANDLING = {_INDICATOR_TYPE_YARA, _INDICATOR_TYPE_CVE}

    _OPENCTI_TO_STIX2 = {
        _OPENCTI_TYPE_DOMAIN: create_object_path("domain-name", ["value"]),
        _OPENCTI_TYPE_IPV4_ADDR: create_object_path("ipv4-addr", ["value"]),
        _OPENCTI_TYPE_IPV6_ADDR: create_object_path("ipv6-addr", ["value"]),
        _OPENCTI_TYPE_URL: create_object_path("url", ["value"]),
        _OPENCTI_TYPE_EMAIL_ADDRESS: create_object_path("email-addr", ["value"]),
        _OPENCTI_TYPE_MUTEX: create_object_path("mutex", ["name"]),
        _OPENCTI_TYPE_FILE_PATH: create_object_path("file", ["name"]),
        _OPENCTI_TYPE_FILE_MD5: create_object_path("file", ["hashes", "MD5"]),
        _OPENCTI_TYPE_FILE_SHA1: create_object_path("file", ["hashes", "SHA1"]),
        _OPENCTI_TYPE_FILE_SHA256: create_object_path("file", ["hashes", "SHA256"]),
    }

    _OBJECT_PATH_YARA = create_object_path("yara", ["value"])

    _PATTERN_TYPE_STIX = "stix"
    _PATTERN_TYPE_YARA = "yara"

    _PATTERN_TYPE_YARA_OBSERVABLE_TYPE = "Unknown"

    _TAG_COLOR = "#489044"

    def __init__(
        self,
        pulse: Pulse,
        author: Identity,
        source_name: str,
        object_marking_refs: List[MarkingDefinition],
        confidence_level: int,
        report_status: int,
        report_type: str,
    ) -> None:
        """Initialize pulse bundle builder."""
        self.logger = logging.getLogger(self.__class__.__name__)

        self.pulse = pulse
        self.author = author
        self.source_name = source_name
        self.object_marking_refs = object_marking_refs
        self.confidence_level = confidence_level
        self.report_status = report_status
        self.report_type = report_type

        self.first_seen = self.pulse.created
        self.last_seen = self.pulse.modified

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        intrusion_sets = []
        adversary = self.pulse.adversary
        if adversary:
            intrusion_set = create_intrusion_set(
                adversary, self.author, self.object_marking_refs
            )
            intrusion_sets.append(intrusion_set)
        return intrusion_sets

    def _create_malwares(self) -> List[Malware]:
        malwares = []
        for malware_family in self.pulse.malware_families:
            if not malware_family:
                continue
            malware = create_malware(
                malware_family, self.author, self.object_marking_refs
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

    def _create_target_sectors(self) -> List[Identity]:
        target_sectors = []
        for industry in self.pulse.industries:
            sector = create_sector(industry, self.author)
            target_sectors.append(sector)
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

    def _create_target_countries(self) -> List[Identity]:
        target_countries = []
        for target_country in self.pulse.targeted_countries:
            country = create_country(target_country, self.author)
            target_countries.append(country)
        return target_countries

    def _create_attack_patterns(self) -> List[AttackPattern]:
        attack_patterns = []
        for attack_id in self.pulse.attack_ids:
            attack_id_clean = attack_id.strip()
            if not attack_id_clean:
                continue

            external_references = create_attack_pattern_external_reference(
                attack_id_clean
            )
            attack_pattern = create_attack_pattern(
                attack_id_clean,
                self.author,
                external_references,
                self.object_marking_refs,
            )
            attack_patterns.append(attack_pattern)
        return attack_patterns

    def _create_vulnerability(self, name) -> Vulnerability:
        vulnerability_external_references = create_vulnerability_external_reference(
            name
        )
        return create_vulnerability(
            name,
            self.author,
            vulnerability_external_references,
            self.object_marking_refs,
        )

    def _create_vulnerabilities(self) -> List[Vulnerability]:
        vulnerabilities = []
        cve_pulse_indicators = list(
            filter(lambda x: x.type == self._INDICATOR_TYPE_CVE, self.pulse.indicators)
        )
        for cve_pulse_indicator in cve_pulse_indicators:
            vulnerability = self._create_vulnerability(cve_pulse_indicator.indicator)
            vulnerabilities.append(vulnerability)
        return vulnerabilities

    def _create_indicator(
        self,
        name: str,
        description: str,
        valid_from: datetime,
        observable_type: str,
        observable_value: str,
        pattern_type: str,
        pattern_value: str,
        indicator_pattern: str,
    ) -> Indicator:
        return create_indicator(
            name,
            self.author,
            description,
            valid_from,
            observable_type,
            observable_value,
            pattern_type,
            pattern_value,
            indicator_pattern,
            self.object_marking_refs,
        )

    @staticmethod
    def _create_indicator_description(pulse_indicator: PulseIndicator) -> str:
        indicator_description = f"{pulse_indicator.title}"
        if pulse_indicator.description:
            if indicator_description:
                indicator_description = (
                    f"{indicator_description}\n{pulse_indicator.description}"
                )
            else:
                indicator_description = f"{pulse_indicator.description}"
        return indicator_description

    def _create_yara_indicators(self) -> List[Indicator]:
        yara_indicators = []
        yara_pulse_indicators = list(
            filter(lambda x: x.type == self._INDICATOR_TYPE_YARA, self.pulse.indicators)
        )
        for yara_pulse_indicator in yara_pulse_indicators:
            observable_type = self._PATTERN_TYPE_YARA_OBSERVABLE_TYPE
            observable_value = yara_pulse_indicator.content

            pattern_type = self._PATTERN_TYPE_YARA

            # Dummy pattern value.
            pattern_value = "[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']"

            # YARA rule as indicator pattern.
            indicator_pattern = yara_pulse_indicator.content

            yara_indicator = self._create_indicator(
                yara_pulse_indicator.indicator,
                self._create_indicator_description(yara_pulse_indicator),
                yara_pulse_indicator.created,
                observable_type,
                observable_value,
                pattern_type,
                pattern_value,
                indicator_pattern,
            )
            yara_indicators.append(yara_indicator)
        return yara_indicators

    def _create_common_indicators(self) -> List[Indicator]:
        common_indicators = []
        pulse_indicators = list(
            filter(
                lambda x: x.type not in self._INDICATOR_TYPES_WITH_SPECIAL_HANDLING,
                self.pulse.indicators,
            )
        )
        for pulse_indicator in pulse_indicators:
            pulse_indicator_type = pulse_indicator.type

            observable_type = self._INDICATOR_TYPE_TO_OPENCTI_TYPE.get(
                pulse_indicator_type
            )
            if observable_type is None:
                self.logger.error(
                    "Unsupported pulse indicator type: %s", pulse_indicator_type
                )
                continue

            observable_value = pulse_indicator.indicator

            pattern_type = self._PATTERN_TYPE_STIX
            pattern_value = create_equality_observation_expression_str(
                self._OPENCTI_TO_STIX2[observable_type], observable_value
            )
            indicator_pattern = pattern_value

            indicator = self._create_indicator(
                pulse_indicator.indicator,
                self._create_indicator_description(pulse_indicator),
                pulse_indicator.created,
                str(observable_type.value),
                observable_value,
                pattern_type,
                pattern_value,
                indicator_pattern,
            )

            common_indicators.append(indicator)
        return common_indicators

    def _create_indicators(self) -> List[Indicator]:
        indicators = []
        indicators.extend(self._create_common_indicators())
        indicators.extend(self._create_yara_indicators())
        return indicators

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

    def _create_report(self, object_refs: List[STIXDomainObject]) -> Report:
        external_references = self._create_report_external_references()
        tags = self._create_report_tags()

        return Report(
            created_by_ref=self.author,
            name=self.pulse.name,
            description=self.pulse.description,
            published=self.pulse.created,
            object_refs=object_refs,
            labels=["threat-report"],
            external_references=external_references,
            object_marking_refs=self.object_marking_refs,
            custom_properties={
                CustomProperties.REPORT_CLASS: self.report_type,
                CustomProperties.OBJECT_STATUS: self.report_status,
                CustomProperties.SRC_CONF_LEVEL: self.confidence_level,
                CustomProperties.TAG_TYPE: tags,
            },
        )

    def _create_report_external_references(self) -> List[ExternalReference]:
        external_references = [self._create_pulse_external_reference()]

        for reference in self.pulse.references:
            if not reference:
                continue
            external_reference = create_external_reference(self.source_name, reference)
            external_references.append(external_reference)

        return external_references

    def _create_pulse_external_reference(self) -> ExternalReference:
        pulse_id = self.pulse.id
        pulse_url = self.pulse.url
        return create_external_reference(self.source_name, pulse_url, pulse_id)

    def _create_report_tags(self) -> List[Mapping[str, str]]:
        tags = []
        for pulse_tag in self.pulse.tags:
            tag = create_tag(self.source_name, pulse_tag, self._TAG_COLOR)
            tags.append(tag)
        return tags

    def _create_reports(self, object_refs: List[STIXDomainObject]) -> List[Report]:
        return [self._create_report(object_refs)]

    def build(self) -> Bundle:
        """Build pulse bundle."""
        # Prepare STIX2 bundle.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_marking_refs)

        # Create intrusion set and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create malwares and add to bundle.
        malwares = self._create_malwares()
        bundle_objects.extend(malwares)

        # Intrusion sets use malwares, add to bundle.
        intrusion_sets_use_malwares = self._create_uses_relationships(
            intrusion_sets, malwares
        )
        bundle_objects.extend(intrusion_sets_use_malwares)

        # Create target sectors and add to bundle.
        target_sectors = self._create_target_sectors()
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

        # Create target countries and add to bundle.
        target_countries = self._create_target_countries()
        bundle_objects.extend(target_countries)

        # Intrusion sets target countries, add to bundle.
        intrusion_sets_target_countries = self._create_targets_relationships(
            intrusion_sets, target_countries
        )
        bundle_objects.extend(intrusion_sets_target_countries)

        # Malwares target countries, add to bundle.
        malwares_target_countries = self._create_targets_relationships(
            malwares, target_countries
        )
        bundle_objects.extend(malwares_target_countries)

        # Create attack patterns and add to bundle.
        attack_patterns = self._create_attack_patterns()
        bundle_objects.extend(attack_patterns)

        # Intrusion sets use attack patterns, add to bundle.
        intrusion_sets_use_attack_patterns = self._create_uses_relationships(
            intrusion_sets, attack_patterns
        )
        bundle_objects.extend(intrusion_sets_use_attack_patterns)

        # Malwares use attack patterns, add to bundle.
        malwares_use_attack_patterns = self._create_uses_relationships(
            malwares, attack_patterns
        )
        bundle_objects.extend(malwares_use_attack_patterns)

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

        # Create indicators and to bundle.
        indicators = self._create_indicators()
        bundle_objects.extend(indicators)

        # Indicator indicates entities, add to bundle.
        indicator_indicates = intrusion_sets + malwares

        indicator_indicates_entities = self._create_indicates_relationships(
            indicators, indicator_indicates
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
            target_countries,
            intrusion_sets_target_countries,
            malwares_target_countries,
            attack_patterns,
            malwares_use_attack_patterns,
            intrusion_sets_use_attack_patterns,
            vulnerabilities,
            intrusion_sets_target_vulnerabilities,
            malwares_target_vulnerabilities,
            indicators,
            indicator_indicates_entities,
        )

        reports = self._create_reports(object_refs)
        bundle_objects.extend(reports)

        return Bundle(objects=bundle_objects)
