# -*- coding: utf-8 -*-
"""OpenCTI CrowdStrike indicator builder module."""

import logging
from typing import List, Mapping, NamedTuple, Optional, Set

from crowdstrike_feeds_services.utils import (
    DEFAULT_X_OPENCTI_SCORE,
    OBSERVATION_FACTORY_CRYPTOCURRENCY_WALLET,
    OBSERVATION_FACTORY_DOMAIN_NAME,
    OBSERVATION_FACTORY_EMAIL_ADDRESS,
    OBSERVATION_FACTORY_EMAIL_MESSAGE_SUBJECT,
    OBSERVATION_FACTORY_FILE_MD5,
    OBSERVATION_FACTORY_FILE_NAME,
    OBSERVATION_FACTORY_FILE_SHA1,
    OBSERVATION_FACTORY_FILE_SHA256,
    OBSERVATION_FACTORY_IPV4_ADDRESS,
    OBSERVATION_FACTORY_MUTEX,
    OBSERVATION_FACTORY_URL,
    OBSERVATION_FACTORY_USER_AGENT,
    ObservableProperties,
    ObservationFactory,
    create_based_on_relationships,
    create_indicates_relationships,
    create_indicator,
    create_intrusion_sets_from_names,
    create_kill_chain_phase,
    create_malware,
    create_object_refs,
    create_sector,
    create_stix2_report_from_report,
    create_targets_relationships,
    create_uses_relationships,
    create_vulnerability,
    create_vulnerability_external_references,
    timestamp_to_datetime,
)
from crowdstrike_feeds_services.utils.report_fetcher import FetchedReport
from stix2 import Bundle, Identity
from stix2 import Indicator as STIXIndicator  # type: ignore
from stix2 import IntrusionSet, KillChainPhase, Malware, MarkingDefinition, Relationship
from stix2 import Report as STIXReport
from stix2 import Vulnerability
from stix2.v21 import _DomainObject, _Observable  # type: ignore

logger = logging.getLogger(__name__)


class Observation(NamedTuple):
    """Observation."""

    observable: Optional[_Observable]
    indicator: Optional[STIXIndicator]
    relationship: Optional[Relationship]


class IndicatorBundleBuilderConfig(NamedTuple):
    """Indicator bundle builder configuration."""

    indicator: dict
    author: Identity
    source_name: str
    object_markings: List[MarkingDefinition]
    confidence_level: int
    create_observables: bool
    create_indicators: bool
    indicator_report_status: int
    indicator_report_type: str
    indicator_reports: List[FetchedReport]
    indicator_low_score: int
    indicator_low_score_labels: Set[str]
    indicator_unwanted_labels: Set[str]


class IndicatorBundleBuilder:
    """Indicator bundle builder."""

    _INDICATOR_TYPE_TO_OBSERVATION_FACTORY = {
        # "binary_string": "",  # Ignore.
        # "compile_time": "",  # Ignore.
        # "device_name": "",  # Ignore.
        "domain": OBSERVATION_FACTORY_DOMAIN_NAME,
        "email_address": OBSERVATION_FACTORY_EMAIL_ADDRESS,
        "email_subject": OBSERVATION_FACTORY_EMAIL_MESSAGE_SUBJECT,
        # "event_name": "",  # Ignore.
        # "file_mapping": "",  # Ignore.
        "file_name": OBSERVATION_FACTORY_FILE_NAME,
        "file_path": OBSERVATION_FACTORY_FILE_NAME,
        # "hash_ion": "",  # Ignore.
        "hash_md5": OBSERVATION_FACTORY_FILE_MD5,
        "hash_sha1": OBSERVATION_FACTORY_FILE_SHA1,
        "hash_sha256": OBSERVATION_FACTORY_FILE_SHA256,
        "ip_address": OBSERVATION_FACTORY_IPV4_ADDRESS,
        "ip_address_block": OBSERVATION_FACTORY_IPV4_ADDRESS,
        "mutex_name": OBSERVATION_FACTORY_MUTEX,
        # "password": "",  # Ignore.
        # "persona_name": "",  # Ignore.
        # "phone_number": "",  # Ignore.
        # "port": "",  # Ignore.
        # "registry": "",  # Ignore.
        # "semaphore_name": "",  # Ignore.
        # XXX: service_name currently not supported by pycti/OpenCTI.
        # "service_name": OBSERVATION_FACTORY_WINDOWS_SERVICE_NAME,
        "url": OBSERVATION_FACTORY_URL,
        "user_agent": OBSERVATION_FACTORY_USER_AGENT,
        # "username": "",  # Ignore.
        # XXX: x509_serial and x509_subject currently not supported by pycti/OpenCTI.
        # "x509_serial": OBSERVATION_FACTORY_X509_CERTIFICATE_SERIAL_NUMBER,
        # "x509_subject": OBSERVATION_FACTORY_X509_CERTIFICATE_SUBJECT,
        "bitcoin_address": OBSERVATION_FACTORY_CRYPTOCURRENCY_WALLET,
        "coin_address": OBSERVATION_FACTORY_CRYPTOCURRENCY_WALLET,
    }

    _INDICATOR_PATTERN_TYPE_STIX = "stix"

    _CS_KILL_CHAIN_TO_LOCKHEED_MARTIN_CYBER_KILL_CHAIN = {
        "Reconnaissance": "reconnaissance",
        "Weaponization": "weaponization",
        "Delivery": "delivery",
        "Exploitation": "exploitation",
        "Installation": "installation",
        "C2": "command-and-control",
        "ActionOnObjectives": "action-on-objectives",
    }

    def __init__(self, config: IndicatorBundleBuilderConfig) -> None:
        """Initialize indicator bundle builder."""
        self.indicator = config.indicator
        self.author = config.author
        self.source_name = config.source_name
        self.object_markings = config.object_markings
        self.confidence_level = config.confidence_level
        self.create_observables = config.create_observables
        self.create_indicators = config.create_indicators
        self.indicator_reports = config.indicator_reports
        self.indicator_report_status = config.indicator_report_status
        self.indicator_report_type = config.indicator_report_type
        self.indicator_low_score = config.indicator_low_score
        self.indicator_low_score_labels = config.indicator_low_score_labels
        self.indicator_unwanted_labels = config.indicator_unwanted_labels

        self.observation_factory = self._get_observation_factory(self.indicator["type"])

        self.first_seen = timestamp_to_datetime(self.indicator["published_date"])

    @classmethod
    def _get_observation_factory(cls, indicator_type: str) -> ObservationFactory:
        factory = cls._INDICATOR_TYPE_TO_OBSERVATION_FACTORY.get(indicator_type)
        if factory is None:
            raise TypeError(f"Unsupported indicator type: {indicator_type}")
        return factory

    def _create_intrusion_sets(self) -> List[IntrusionSet]:
        indicator_actors = self.indicator["actors"]
        if not indicator_actors:
            return []

        return create_intrusion_sets_from_names(
            indicator_actors,
            created_by=self.author,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
        )

    def _create_kill_chain_phases(self) -> List[KillChainPhase]:
        kill_chain_phases = []

        for kill_chain in self.indicator["kill_chains"]:
            lh_kill_chain = self._CS_KILL_CHAIN_TO_LOCKHEED_MARTIN_CYBER_KILL_CHAIN.get(
                kill_chain
            )
            if lh_kill_chain is None:
                logger.warning("Unknown kill chain: %s", kill_chain)
                continue

            kill_chain_phase = self._create_kill_chain_phase(lh_kill_chain)
            kill_chain_phases.append(kill_chain_phase)

        return kill_chain_phases

    @staticmethod
    def _create_kill_chain_phase(phase_name: str) -> KillChainPhase:
        return create_kill_chain_phase("lockheed-martin-cyber-kill-chain", phase_name)

    def _create_malwares(
        self, kill_chain_phases: List[KillChainPhase]
    ) -> List[Malware]:
        indicator_malware_families = self.indicator["malware_families"]
        if not indicator_malware_families:
            return []

        malwares = []

        for indicator_malware_family in indicator_malware_families:
            malware = self._create_malware(indicator_malware_family, kill_chain_phases)
            malwares.append(malware)

        return malwares

    def _create_malware(
        self, name: str, kill_chain_phases: List[KillChainPhase]
    ) -> Malware:
        return create_malware(
            name,
            created_by=self.author,
            is_family=True,
            kill_chain_phases=kill_chain_phases,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
        )

    def _create_uses_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_uses_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
            start_time=self.first_seen,
        )

    def _create_targeted_sectors(self) -> List[Identity]:
        target_sectors = []
        for target in self.indicator["targets"]:
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
            self.confidence_level,
            self.object_markings,
            start_time=self.first_seen,
        )

    def _create_vulnerability(self, name: str):
        external_references = create_vulnerability_external_references(name)

        return create_vulnerability(
            name,
            created_by=self.author,
            confidence=self.confidence_level,
            external_references=external_references,
            object_markings=self.object_markings,
        )

    def _create_vulnerabilities(self) -> List[Vulnerability]:
        vulnerabilities = []

        for vulnerability_name in self.indicator["vulnerabilities"]:
            vulnerability = self._create_vulnerability(vulnerability_name)
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _create_observation(
        self, kill_chain_phases: List[KillChainPhase]
    ) -> Optional[Observation]:
        if not (self.create_observables or self.create_indicators):
            return None

        # Get the labels.
        labels = self._get_labels()

        # Skip indicators with labels entered in config
        for label in labels:
            label = label.lower()
            if label in self.indicator_unwanted_labels:
                return None

        # Determine the score based on the labels.
        score = self._determine_score_by_labels(labels)

        # Create an observable.
        observable = self._create_observable(labels, score)

        # Create an indicator.
        indicator = self._create_indicator(kill_chain_phases, labels, score)

        # Create a based on relationship.
        indicator_based_on_observable = None
        if indicator is not None and observable is not None:
            based_on_relationship = self._create_based_on_relationships(
                [indicator], [observable]
            )
            indicator_based_on_observable = based_on_relationship[0]

        return Observation(observable, indicator, indicator_based_on_observable)

    def _get_labels(self) -> List[str]:
        labels = []

        indicator_labels = self.indicator["labels"]
        for indicator_label in indicator_labels:
            label = indicator_label["name"]
            if not label:
                continue

            labels.append(label)

        return labels

    def _create_observable(
        self, labels: List[str], score: int
    ) -> Optional[_Observable]:
        if not self.create_observables:
            return None

        indicator_value = self.indicator["indicator"]

        observable_properties = self._create_observable_properties(
            indicator_value, labels, score
        )
        observable = self.observation_factory.create_observable(observable_properties)

        return observable

    def _create_observable_properties(
        self,
        value: str,
        labels: List[str],
        score: int,
    ) -> ObservableProperties:
        return ObservableProperties(
            value=value,
            created_by=self.author,
            labels=labels,
            score=score,
            object_markings=self.object_markings,
        )

    def _determine_score_by_labels(self, labels: List[str]) -> int:
        score = DEFAULT_X_OPENCTI_SCORE

        for label in labels:
            if label in self.indicator_low_score_labels:
                score = self.indicator_low_score
                break

        return score

    def _create_indicator(
        self,
        kill_chain_phases: List[KillChainPhase],
        labels: List[str],
        score: int,
    ) -> Optional[STIXIndicator]:
        if not self.create_indicators:
            return None

        indicator_value = self.indicator["indicator"]
        indicator_pattern = self.observation_factory.create_indicator_pattern(
            indicator_value
        )
        indicator_pattern_type = self._INDICATOR_PATTERN_TYPE_STIX
        indicator_published = timestamp_to_datetime(self.indicator["published_date"])

        return create_indicator(
            indicator_pattern.pattern,
            indicator_pattern_type,
            created_by=self.author,
            name=indicator_value,
            valid_from=indicator_published,
            kill_chain_phases=kill_chain_phases,
            labels=labels,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
            x_opencti_main_observable_type=indicator_pattern.main_observable_type,
            x_opencti_score=score,
        )

    def _create_based_on_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_based_on_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
        )

    def _create_indicates_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[Relationship]:
        return create_indicates_relationships(
            self.author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
            start_time=self.first_seen,
        )

    def _create_report(
        self,
        report: dict,
        report_files: List[Mapping[str, str]],
        objects: List[_DomainObject],
    ) -> STIXReport:
        return create_stix2_report_from_report(
            report,
            self.source_name,
            self.author,
            objects,
            [self.indicator_report_type],
            self.confidence_level,
            self.object_markings,
            self.indicator_report_status,
            report_files,
        )

    def _create_reports(self, objects: List[_DomainObject]) -> List[STIXReport]:
        reports = []

        for indicator_report in self.indicator_reports:
            report = self._create_report(
                indicator_report["report"], indicator_report["files"], objects
            )
            reports.append(report)

        return reports

    def build(self) -> Optional[Bundle]:
        """Build indicator bundle."""
        # Create bundle with author.
        bundle_objects = [self.author]

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create kill chain phases.
        kill_chain_phases = self._create_kill_chain_phases()

        # Create malwares and add to bundle.
        malwares = self._create_malwares(kill_chain_phases)
        bundle_objects.extend(malwares)

        # Intrusion sets use malwares and add to bundle.
        intrusion_sets_use_malwares = self._create_uses_relationships(
            intrusion_sets, malwares
        )
        bundle_objects.extend(intrusion_sets_use_malwares)

        # Create target sectors and add to bundle.
        target_sectors = self._create_targeted_sectors()
        bundle_objects.extend(target_sectors)

        # Intrusion sets target sectors and add to bundle.
        intrusion_sets_target_sectors = self._create_targets_relationships(
            intrusion_sets, target_sectors
        )
        bundle_objects.extend(intrusion_sets_target_sectors)

        # Malwares target sectors and add to bundle.
        malwares_target_sectors = self._create_targets_relationships(
            malwares, target_sectors
        )
        bundle_objects.extend(malwares_target_sectors)

        # Create vulnerabilities and add to bundle.
        vulnerabilities = self._create_vulnerabilities()
        bundle_objects.extend(vulnerabilities)

        # Intrusion sets target vulnerabilities and add to bundle.
        intrusion_sets_target_vulnerabilities = self._create_targets_relationships(
            intrusion_sets, vulnerabilities
        )
        bundle_objects.extend(intrusion_sets_target_vulnerabilities)

        # Malwares target vulnerabilities and add to bundle.
        malwares_target_vulnerabilities = self._create_targets_relationships(
            malwares, vulnerabilities
        )
        bundle_objects.extend(malwares_target_vulnerabilities)

        # Create observations.
        observation = self._create_observation(kill_chain_phases)
        if observation is None:
            logger.error("No indicator nor observable for %s", self.indicator["id"])
            return None

        # Get observables and add to bundle.
        observables = []
        if observation.observable is not None:
            observables.append(observation.observable)
        bundle_objects.extend(observables)

        # Get indicators and add to bundle.
        indicators = []
        if observation.indicator is not None:
            indicators.append(observation.indicator)
        bundle_objects.extend(indicators)

        # Get observation relationships and add to bundle.
        indicators_based_on_observables = []
        if observation.relationship is not None:
            indicators_based_on_observables.append(observation.relationship)
        bundle_objects.extend(indicators_based_on_observables)

        # Indicator(s) indicate entities and add to bundle.
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
            vulnerabilities,
            intrusion_sets_target_vulnerabilities,
            malwares_target_vulnerabilities,
            observables,
            indicators,
            indicators_based_on_observables,
            indicator_indicates_entities,
        )

        # Create reports and add to bundle.
        reports = self._create_reports(object_refs)
        bundle_objects.extend(reports)

        # XXX: Without allow_custom=True the observable with the custom property
        # will cause an unexpected property (x_opencti_score) error.
        return Bundle(objects=bundle_objects, allow_custom=True)
