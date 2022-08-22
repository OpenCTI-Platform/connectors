"""OpenCTI AlienVault builder module."""

import logging
from datetime import datetime
from typing import Callable, List, Mapping, NamedTuple, Optional, Set

import stix2
from alienvault.models import Pulse, PulseIndicator
from alienvault.utils import (
    OBSERVATION_FACTORY_CRYPTOCURRENCY_WALLET,
    OBSERVATION_FACTORY_DOMAIN_NAME,
    OBSERVATION_FACTORY_EMAIL_ADDRESS,
    OBSERVATION_FACTORY_FILE_MD5,
    OBSERVATION_FACTORY_FILE_NAME,
    OBSERVATION_FACTORY_FILE_SHA1,
    OBSERVATION_FACTORY_FILE_SHA256,
    OBSERVATION_FACTORY_HOSTNAME,
    OBSERVATION_FACTORY_IPV4_ADDRESS,
    OBSERVATION_FACTORY_IPV6_ADDRESS,
    OBSERVATION_FACTORY_MUTEX,
    OBSERVATION_FACTORY_URL,
    ObservableProperties,
    ObservationFactory,
    create_attack_pattern,
    create_attack_pattern_external_reference,
    create_based_on_relationships,
    create_country,
    create_external_reference,
    create_indicates_relationships,
    create_indicator,
    create_intrusion_set,
    create_malware,
    create_object_refs,
    create_organization,
    create_report,
    create_sector,
    create_targets_relationships,
    create_uses_relationships,
    create_vulnerability,
    create_vulnerability_external_reference,
    get_tlp_string_marking_definition,
)
from stix2.v21 import _DomainObject, _Observable  # type: ignore

log = logging.getLogger(__name__)


class Observation(NamedTuple):
    """Observation."""

    observable: Optional[_Observable]
    indicator: Optional[stix2.Indicator]
    relationship: Optional[stix2.Relationship]


class PulseBundleBuilderConfig(NamedTuple):
    """Pulse bundle builder configuration."""

    pulse: Pulse
    provider: stix2.Identity
    source_name: str
    object_markings: List[stix2.MarkingDefinition]
    create_observables: bool
    create_indicators: bool
    confidence_level: int
    report_status: int
    report_type: str
    guessed_malwares: Mapping[str, str]
    guessed_cves: Set[str]
    excluded_pulse_indicator_types: Set[str]
    enable_relationships: bool
    enable_attack_patterns_indicates: bool


class PulseBundleBuilder:
    """Pulse bundle builder."""

    _DUMMY_OBJECT_NAME = "AV EMPTY REPORT"

    _PULSE_INDICATOR_TYPE_TO_OBSERVATION_FACTORY: Mapping[str, ObservationFactory] = {
        "IPv4": OBSERVATION_FACTORY_IPV4_ADDRESS,
        "IPv6": OBSERVATION_FACTORY_IPV6_ADDRESS,
        "domain": OBSERVATION_FACTORY_DOMAIN_NAME,
        "hostname": OBSERVATION_FACTORY_HOSTNAME,
        "email": OBSERVATION_FACTORY_EMAIL_ADDRESS,
        "URL": OBSERVATION_FACTORY_URL,
        "URI": OBSERVATION_FACTORY_URL,
        "FileHash-MD5": OBSERVATION_FACTORY_FILE_MD5,
        "FileHash-SHA1": OBSERVATION_FACTORY_FILE_SHA1,
        "FileHash-SHA256": OBSERVATION_FACTORY_FILE_SHA256,
        # "FileHash-PEHASH": "",  # Ignore.
        # "FileHash-IMPHASH": "",  # Ignore.
        "CIDR": OBSERVATION_FACTORY_IPV4_ADDRESS,
        "FilePath": OBSERVATION_FACTORY_FILE_NAME,
        "Mutex": OBSERVATION_FACTORY_MUTEX,
        # "CVE": "",  # Custom handling, will be converted into a vulnerability.
        # "YARA": "",  # Custom handling, will be converted into a YARA indicator.
        # "JA3": "",  # Ignore.
        # "osquery": "",  # Ignore.
        # "SSLCertFingerprint": "",  # Ignore.
        "BitcoinAddress": OBSERVATION_FACTORY_CRYPTOCURRENCY_WALLET,
    }

    # Following Pulse indicator types require special handling.
    _PULSE_INDICATOR_TYPE_YARA = "YARA"
    _PULSE_INDICATOR_TYPE_CVE = "CVE"

    _PULSE_INDICATOR_TYPES_WITH_SPECIAL_HANDLING = {
        _PULSE_INDICATOR_TYPE_YARA,
        _PULSE_INDICATOR_TYPE_CVE,
    }

    # STIX2 indicator pattern types.
    _INDICATOR_PATTERN_TYPE_STIX = "stix"
    _INDICATOR_PATTERN_TYPE_YARA = "yara"

    def __init__(
        self,
        config: PulseBundleBuilderConfig,
    ) -> None:
        """Initialize pulse bundle builder."""
        self.pulse = config.pulse
        self.provider = config.provider
        self.pulse_author = self._determine_pulse_author(self.pulse, self.provider)
        self.source_name = config.source_name
        self.object_markings = self._determine_pulse_tlp(
            self.pulse, config.object_markings
        )
        self.confidence_level = config.confidence_level
        self.create_observables = config.create_observables
        self.create_indicators = config.create_indicators
        self.report_status = config.report_status
        self.report_type = config.report_type
        self.guessed_malwares = config.guessed_malwares
        self.guessed_cves = config.guessed_cves
        self.excluded_pulse_indicator_types = config.excluded_pulse_indicator_types
        self.enable_relationships = config.enable_relationships
        self.enable_attack_patterns_indicates = config.enable_attack_patterns_indicates

    def _no_relationships(self) -> bool:
        return not self.enable_relationships

    def _no_indicates(self) -> bool:
        return not self.enable_attack_patterns_indicates

    @staticmethod
    def _determine_pulse_author(
        pulse: Pulse, provider: stix2.Identity
    ) -> stix2.Identity:
        pulse_author = pulse.author_name
        if not pulse_author:
            return provider
        if pulse_author == provider.name:
            return provider
        return create_organization(pulse_author, created_by=provider)

    @staticmethod
    def _determine_pulse_tlp(
        pulse: Pulse, default_object_markings: List[stix2.MarkingDefinition]
    ) -> List[stix2.MarkingDefinition]:
        pulse_tlp = pulse.tlp
        try:
            return [get_tlp_string_marking_definition(pulse_tlp)]
        except ValueError as e:
            log.warning("Unable to determine TLP for pulse: %s", str(e))
            return default_object_markings

    def _create_authors(self) -> List[stix2.Identity]:
        authors = []
        if self.pulse_author is not self.provider:
            authors.append(self.provider)
        authors.append(self.pulse_author)
        return authors

    def _create_intrusion_sets(self) -> List[stix2.IntrusionSet]:
        intrusion_sets = []
        adversary = self.pulse.adversary
        if adversary is not None and adversary:
            intrusion_set = self._create_intrusion_set(adversary)
            intrusion_sets.append(intrusion_set)
        return intrusion_sets

    def _create_intrusion_set(self, name: str) -> stix2.IntrusionSet:
        return create_intrusion_set(
            name, self.pulse_author, self.confidence_level, self.object_markings
        )

    def _create_malwares(self) -> List[stix2.Malware]:
        malware_list = []

        # Create malwares based on guessed malwares.
        for name, standard_id in self.guessed_malwares.items():
            malware = self._create_malware(name, malware_id=standard_id)
            malware_list.append(malware)

        # Create malwares based on malware families in the Pulse.
        for malware_name in self.pulse.malware_families:
            if not malware_name or malware_name in self.guessed_malwares:
                continue

            malware = self._create_malware(malware_name)
            malware_list.append(malware)

        return malware_list

    def _create_malware(
        self, name: str, malware_id: Optional[str] = None
    ) -> stix2.Malware:
        return create_malware(
            name,
            self.pulse_author,
            self.confidence_level,
            self.object_markings,
            malware_id=malware_id,
        )

    def _create_uses_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[stix2.Relationship]:
        if self._no_relationships():
            return []

        return create_uses_relationships(
            self.pulse_author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
        )

    def _create_target_sectors(self) -> List[stix2.Identity]:
        target_sectors = []
        for industry in self.pulse.industries:
            if not industry:
                continue
            sector = create_sector(industry, self.pulse_author)
            target_sectors.append(sector)
        return target_sectors

    def _create_targets_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[stix2.Relationship]:
        if self._no_relationships():
            return []

        return create_targets_relationships(
            self.pulse_author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
        )

    def _create_target_countries(self) -> List[stix2.Identity]:
        target_countries = []
        for target_country in self.pulse.targeted_countries:
            if not target_country:
                continue

            country = self._create_country(target_country)
            target_countries.append(country)
        return target_countries

    def _create_country(self, name: str) -> stix2.Identity:
        return create_country(name, self.pulse_author)

    def _create_attack_patterns(self) -> List[stix2.AttackPattern]:
        attack_patterns = []
        for attack_id in self.pulse.attack_ids:
            attack_id_clean = attack_id.strip()
            if not attack_id_clean:
                continue

            attack_pattern = self._create_attack_pattern(attack_id_clean)
            attack_patterns.append(attack_pattern)
        return attack_patterns

    def _create_attack_pattern(self, name: str) -> stix2.AttackPattern:
        external_references = create_attack_pattern_external_reference(name)

        return create_attack_pattern(
            name,
            self.pulse_author,
            self.confidence_level,
            external_references,
            self.object_markings,
        )

    def _create_vulnerabilities(self) -> List[stix2.Vulnerability]:
        vulnerabilities = []

        for guessed_cve in self.guessed_cves:
            vulnerability = self._create_vulnerability(guessed_cve)
            vulnerabilities.append(vulnerability)

        cve_pulse_indicators = self._get_pulse_indicators(
            lambda x: x.type == self._PULSE_INDICATOR_TYPE_CVE
        )
        cve_pulse_indicators = self._filter_pulse_indicators_excluded_types(
            cve_pulse_indicators
        )

        for cve_pulse_indicator in cve_pulse_indicators:
            cve = cve_pulse_indicator.indicator
            if cve in self.guessed_cves:
                continue

            vulnerability = self._create_vulnerability(cve)
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _get_pulse_indicators(
        self, filter_func: Callable[[PulseIndicator], bool]
    ) -> List[PulseIndicator]:
        return self._filter_pulse_indicators(filter_func, self.pulse.indicators)

    @staticmethod
    def _filter_pulse_indicators(
        filter_func: Callable[[PulseIndicator], bool],
        pulse_indicators: List[PulseIndicator],
    ) -> List[PulseIndicator]:
        return list(filter(filter_func, pulse_indicators))

    def _create_vulnerability(self, name) -> stix2.Vulnerability:
        external_references = create_vulnerability_external_reference(name)

        return create_vulnerability(
            name,
            self.pulse_author,
            self.confidence_level,
            external_references,
            self.object_markings,
        )

    def _create_observations(
        self,
    ) -> List[Observation]:
        if not (self.create_observables or self.create_indicators):
            return []

        labels = self._get_labels()

        observations = []

        pulse_indicators = self._get_pulse_indicators(
            lambda x: x.type not in self._PULSE_INDICATOR_TYPES_WITH_SPECIAL_HANDLING
        )
        pulse_indicators = self._filter_pulse_indicators_excluded_types(
            pulse_indicators
        )

        for pulse_indicator in pulse_indicators:
            pulse_indicator_type = pulse_indicator.type
            pulse_indicator_value = pulse_indicator.indicator

            factory = self._PULSE_INDICATOR_TYPE_TO_OBSERVATION_FACTORY.get(
                pulse_indicator_type
            )
            if factory is None:
                log.warning(
                    "Unsupported pulse indicator type: %s",
                    pulse_indicator_type,
                )
                continue

            # Create an observable.
            observable = None

            if self.create_observables:
                observable_properties = self._create_observable_properties(
                    pulse_indicator_value, labels
                )
                observable = factory.create_observable(observable_properties)

            # Create an indicator.
            indicator = None
            indicator_based_on_observable = None

            if self.create_indicators:
                indicator_pattern = factory.create_indicator_pattern(
                    pulse_indicator_value
                )
                pattern_type = self._INDICATOR_PATTERN_TYPE_STIX

                indicator = self._create_indicator(
                    pulse_indicator_value,
                    self._create_indicator_description(pulse_indicator),
                    indicator_pattern.pattern,
                    pattern_type,
                    pulse_indicator.created,
                    labels,
                    main_observable_type=indicator_pattern.main_observable_type,
                )

                if observable is not None:
                    based_on_relationship = self._create_based_on_relationships(
                        [indicator], [observable]
                    )
                    indicator_based_on_observable = based_on_relationship[0]

            observation = Observation(
                observable, indicator, indicator_based_on_observable
            )
            observations.append(observation)

        return observations

    def _filter_pulse_indicators_excluded_types(
        self, pulse_indicators: List[PulseIndicator]
    ) -> List[PulseIndicator]:
        excluded_types = self.excluded_pulse_indicator_types

        def _exclude_pulse_indicator_types_filter(
            pulse_indicator: PulseIndicator,
        ) -> bool:
            indicator_type = pulse_indicator.type
            if indicator_type in excluded_types:
                log.debug(
                    "Excluding pulse indicator '%s' (%s)",
                    pulse_indicator.indicator,
                    indicator_type,
                )
                return False
            else:
                return True

        return self._filter_pulse_indicators(
            _exclude_pulse_indicator_types_filter, pulse_indicators
        )

    def _create_observable_properties(
        self, value: str, labels: List[str]
    ) -> ObservableProperties:
        return ObservableProperties(
            value, self.pulse_author, labels, self.object_markings
        )

    def _create_indicator(
        self,
        name: str,
        description: str,
        pattern: str,
        pattern_type: str,
        valid_from: datetime,
        labels: List[str],
        main_observable_type: Optional[str] = None,
    ) -> stix2.Indicator:
        return create_indicator(
            pattern,
            pattern_type,
            created_by=self.pulse_author,
            name=name,
            description=description,
            valid_from=valid_from,
            labels=labels,
            confidence=self.confidence_level,
            object_markings=self.object_markings,
            x_opencti_main_observable_type=main_observable_type,
        )

    @staticmethod
    def _create_indicator_description(pulse_indicator: PulseIndicator) -> str:
        final_description = ""

        indicator_title = pulse_indicator.title
        if indicator_title is not None and indicator_title:
            final_description = f"{indicator_title}"

        indicator_description = pulse_indicator.description
        if indicator_description is not None and indicator_description:
            if final_description:
                final_description = f"{final_description}\n{indicator_description}"
            else:
                final_description = f"{indicator_description}"

        return final_description

    def _create_yara_indicators(self) -> List[stix2.Indicator]:
        if not self.create_indicators:
            return []

        labels = self._get_labels()

        yara_indicators = []

        yara_pulse_indicators = self._get_pulse_indicators(
            lambda x: x.type == self._PULSE_INDICATOR_TYPE_YARA
        )
        yara_pulse_indicators = self._filter_pulse_indicators_excluded_types(
            yara_pulse_indicators
        )

        for yara_pulse_indicator in yara_pulse_indicators:
            yara_rule_str = yara_pulse_indicator.content
            if yara_rule_str is None or not yara_rule_str:
                continue

            name = yara_pulse_indicator.title
            if name is None or not name:
                name = yara_pulse_indicator.indicator

            pattern = yara_rule_str
            pattern_type = self._INDICATOR_PATTERN_TYPE_YARA

            yara_indicator = self._create_indicator(
                name,
                self._create_indicator_description(yara_pulse_indicator),
                pattern,
                pattern_type,
                yara_pulse_indicator.created,
                labels,
            )
            yara_indicators.append(yara_indicator)
        return yara_indicators

    def _create_indicates_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[stix2.Relationship]:
        if self._no_relationships():
            return []
        new_targets = targets
        if self._no_indicates():
            new_targets = []
            for target in targets:
                if target["type"] != "attack-pattern":
                    new_targets.append(target)

        return create_indicates_relationships(
            self.pulse_author,
            sources,
            new_targets,
            self.confidence_level,
            self.object_markings,
        )

    def _create_based_on_relationships(
        self, sources: List[_DomainObject], targets: List[_DomainObject]
    ) -> List[stix2.Relationship]:
        return create_based_on_relationships(
            self.pulse_author,
            sources,
            targets,
            self.confidence_level,
            self.object_markings,
        )

    def _create_report(self, objects: List[_DomainObject]) -> stix2.Report:
        external_references = self._create_report_external_references()
        labels = self._get_labels()

        return create_report(
            self.pulse.name,
            self.pulse.created,
            objects,
            created_by=self.pulse_author,
            created=self.pulse.created,
            modified=self.pulse.modified,
            description=self.pulse.description,
            report_types=[self.report_type],
            labels=labels,
            confidence=self.confidence_level,
            external_references=external_references,
            object_markings=self.object_markings,
            x_opencti_report_status=self.report_status,
        )

    def _create_report_external_references(self) -> List[stix2.ExternalReference]:
        external_references = [self._create_pulse_external_reference()]

        for reference in self.pulse.references:
            # Exclude empty strings and not URLs.
            if not reference or not reference.startswith("http"):
                continue

            external_reference = self._create_external_reference(reference)
            external_references.append(external_reference)

        return external_references

    def _create_pulse_external_reference(self) -> stix2.ExternalReference:
        pulse_id = self.pulse.id
        pulse_url = self.pulse.url
        return self._create_external_reference(pulse_url, external_id=pulse_id)

    def _create_external_reference(
        self, url: str, external_id: Optional[str] = None
    ) -> stix2.ExternalReference:
        return create_external_reference(self.source_name, url, external_id=external_id)

    def _get_labels(self) -> List[str]:
        labels = []
        for tag in self.pulse.tags:
            if not tag:
                continue
            labels.append(tag)
        return labels

    def _create_reports(self, objects: List[_DomainObject]) -> List[stix2.Report]:
        return [self._create_report(objects)]

    def build(self) -> stix2.Bundle:
        """Build pulse bundle."""
        # Prepare STIX2 bundle.
        bundle_objects = []

        # Create author(s) and add to bundle.
        authors = self._create_authors()
        bundle_objects.extend(authors)

        # Add object marking definitions to bundle.
        bundle_objects.extend(self.object_markings)

        # Create intrusion sets and add to bundle.
        intrusion_sets = self._create_intrusion_sets()
        bundle_objects.extend(intrusion_sets)

        # Create malwares and add to bundle.
        malwares = self._create_malwares()
        bundle_objects.extend(malwares)

        # Intrusion sets use malwares and add to bundle.
        intrusion_sets_use_malwares = self._create_uses_relationships(
            intrusion_sets, malwares
        )
        bundle_objects.extend(intrusion_sets_use_malwares)

        # Create attack patterns and add to bundle.
        attack_patterns = self._create_attack_patterns()
        bundle_objects.extend(attack_patterns)

        # Intrusion sets use attack patterns and add to bundle.
        intrusion_sets_use_attack_patterns = self._create_uses_relationships(
            intrusion_sets, attack_patterns
        )
        bundle_objects.extend(intrusion_sets_use_attack_patterns)

        # Malwares use attack patterns and add to bundle.
        malwares_use_attack_patterns = self._create_uses_relationships(
            malwares, attack_patterns
        )
        bundle_objects.extend(malwares_use_attack_patterns)

        # Create target sectors and add to bundle.
        target_sectors = self._create_target_sectors()
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

        # Create target countries and add to bundle.
        target_countries = self._create_target_countries()
        bundle_objects.extend(target_countries)

        # Intrusion sets target countries and add to bundle.
        intrusion_sets_target_countries = self._create_targets_relationships(
            intrusion_sets, target_countries
        )
        bundle_objects.extend(intrusion_sets_target_countries)

        # Malwares target countries and add to bundle.
        malwares_target_countries = self._create_targets_relationships(
            malwares, target_countries
        )
        bundle_objects.extend(malwares_target_countries)

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

        # Attack patterns target vulnerabilities and add to bundle.
        attack_patterns_target_vulnerabilities = self._create_targets_relationships(
            attack_patterns, vulnerabilities
        )
        bundle_objects.extend(attack_patterns_target_vulnerabilities)

        # Create observations.
        observations = self._create_observations()

        # Get observables and add to bundle.
        observables = [o.observable for o in observations if o.observable is not None]
        bundle_objects.extend(observables)

        # Get indicators, create YARA indicators and to bundle.
        indicators = [o.indicator for o in observations if o.indicator is not None]
        indicators.extend(self._create_yara_indicators())
        bundle_objects.extend(indicators)

        # Get observation relationships and add to bundle.
        indicators_based_on_observables = [
            o.relationship for o in observations if o.relationship is not None
        ]
        bundle_objects.extend(indicators_based_on_observables)

        # Indicator indicates entities and add to bundle.
        indicator_indicates = intrusion_sets + malwares + attack_patterns

        indicator_indicates_entities = self._create_indicates_relationships(
            indicators, indicator_indicates
        )
        bundle_objects.extend(indicator_indicates_entities)

        # Create object references for the report.
        object_refs = create_object_refs(
            intrusion_sets,
            malwares,
            intrusion_sets_use_malwares,
            attack_patterns,
            malwares_use_attack_patterns,
            intrusion_sets_use_attack_patterns,
            target_sectors,
            intrusion_sets_target_sectors,
            malwares_target_sectors,
            target_countries,
            intrusion_sets_target_countries,
            malwares_target_countries,
            vulnerabilities,
            intrusion_sets_target_vulnerabilities,
            malwares_target_vulnerabilities,
            attack_patterns_target_vulnerabilities,
            observables,
            indicators,
            indicators_based_on_observables,
            indicator_indicates_entities,
        )

        # Hack, the report must have at least on object reference.
        if not object_refs:
            log.warning(
                "Pulse has no objects, inserting a dummy object: %s (%s)",
                self.pulse.name,
                self.pulse.id,
            )

            dummy_object = self._create_dummy_object()

            bundle_objects.append(dummy_object)
            object_refs.append(dummy_object)

        # Create a report and add to bundle.
        reports = self._create_reports(object_refs)
        bundle_objects.extend(reports)

        # XXX: Without allow_custom=True the observable with the custom property
        # will cause an unexpected property (x_opencti_score) error.
        log.info(f"Bundling {len(bundle_objects)} objects")
        return stix2.Bundle(objects=bundle_objects, allow_custom=True)

    def _create_dummy_object(self) -> stix2.Identity:
        return create_organization(self._DUMMY_OBJECT_NAME, self.pulse_author)
