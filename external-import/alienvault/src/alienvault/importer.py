"""OpenCTI AlienVault importer module."""

import re
from datetime import datetime
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Set

import stix2
from alienvault.builder import PulseBundleBuilder, PulseBundleBuilderConfig
from alienvault.client import AlienVaultClient
from alienvault.models import Pulse
from alienvault.utils import iso_datetime_str_to_datetime
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper
from stix2.exceptions import STIXError


class PulseImporterConfig(NamedTuple):
    """Pulse importer configuration."""

    helper: OpenCTIConnectorHelper
    client: AlienVaultClient
    author: stix2.Identity
    tlp_marking: stix2.MarkingDefinition
    create_observables: bool
    create_indicators: bool
    update_existing_data: bool
    default_latest_timestamp: str
    report_status: int
    report_type: str
    guess_malware: bool
    guess_cve: bool
    excluded_pulse_indicator_types: Set[str]
    filter_indicators: bool
    enable_relationships: bool
    enable_attack_patterns_indicates: bool
    pulse_blacklist : Set[str]
    malware_blacklist: Set[str]


class PulseImporter:
    """AlienVault pulse importer."""

    _LATEST_PULSE_TIMESTAMP = "latest_pulse_timestamp"

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"

    _GUESS_CVE_PATTERN = r"(CVE-\d{4}-\d{4,7})"

    _STATE_UPDATE_INTERVAL_COUNT = 20

    def __init__(
        self,
        config: PulseImporterConfig,
    ) -> None:
        """Initialize AlienVault indicator importer."""
        self.helper = config.helper
        self.client = config.client
        self.author = config.author
        self.tlp_marking = config.tlp_marking
        self.create_observables = config.create_observables
        self.create_indicators = config.create_indicators
        self.filter_indicators = config.filter_indicators
        self.update_existing_data = config.update_existing_data
        self.default_latest_timestamp = config.default_latest_timestamp
        self.report_status = config.report_status
        self.report_type = config.report_type
        self.guess_malware = config.guess_malware
        self.guess_cve = config.guess_cve
        self.excluded_pulse_indicator_types = config.excluded_pulse_indicator_types
        self.enable_relationships = config.enable_relationships
        self.enable_attack_patterns_indicates = config.enable_attack_patterns_indicates

        self.pulse_blacklist = config.pulse_blacklist
        self.malware_blacklist: Set[str] = config.malware_blacklist
        self.malware_guess_cache: Dict[str, str] = {}
        self.guess_cve_pattern = re.compile(self._GUESS_CVE_PATTERN, re.IGNORECASE)
        self.work_id: Optional[str] = None

    def run(self, state: Dict[str, Any], work_id: str) -> Dict[str, Any]:
        """Run importer."""
        self.work_id = work_id

        self._info(
            "Running pulse importer ("
            "update data: {0}, "
            "guess malware: {1}, "
            "guess cve: {2}, "
            "relationships: {3}, "
            "patterns_indicates: {4}, "
            "filter_indicators: {5}"
            ")...",
            self.update_existing_data,
            self.guess_malware,
            self.guess_cve,
            self.enable_relationships,
            self.enable_attack_patterns_indicates,
            self.filter_indicators,
        )

        self._clear_malware_guess_cache()

        latest_pulse_datetime = self._get_latest_pulse_datetime_from_state(state)

        self._info("Fetching subscribed pulses...")
        pulses = self._fetch_subscribed_pulses(latest_pulse_datetime)
        pulse_count = len(pulses)

        self._info("{0} pulse(s) since {1}...", pulse_count, latest_pulse_datetime)

        self.report_cache = []

        self._get_present_reports()

        if self.filter_indicators:
            total_remaining = 0
            total_filtered = 0
            for i, pulse in enumerate(pulses, start=1):
                before_count = len(pulse.indicators)
                pulse.indicators = [
                    ind
                    for ind in pulse.indicators
                    if ind.created >= latest_pulse_datetime
                ]
                after_count = len(pulse.indicators)
                total_remaining += after_count
                total_filtered += before_count - after_count
                self._info(
                    "({3}/{4}) Filtered {0} indicators past {1} from {2}",
                    total_filtered,
                    latest_pulse_datetime,
                    pulse.name,
                    i,
                    pulse_count,
                )
            if total_filtered > 0:
                self._info(
                    "Filtered {0} total indicators past {1} ({2} remaining)",
                    total_filtered,
                    latest_pulse_datetime,
                    total_remaining,
                )
            else:
                self._info("No indicators to filter")

        failed = 0
        new_state = state.copy()
        latest_pulse_modified_datetime = latest_pulse_datetime

        for count, pulse in enumerate(pulses, start=1):

            if pulse.name in self.pulse_blacklist:
                continue

            result = self._process_pulse(pulse)
            if not result:
                failed += 1

            pulse_modified_datetime = pulse.modified
            if pulse_modified_datetime > latest_pulse_modified_datetime:
                latest_pulse_modified_datetime = pulse_modified_datetime

            if count % self._STATE_UPDATE_INTERVAL_COUNT == 0:  # noqa: S001
                self._info(
                    "Store state: {0}: {1}", count, latest_pulse_modified_datetime
                )
                new_state.update(
                    self._create_pulse_state(latest_pulse_modified_datetime)
                )
                self._set_state(new_state)

        imported = pulse_count - failed

        self._info(
            "Pulse importer completed (imported: {0}, failed: {1}, total: {2}), latest fetch {3}",  # noqa: E501
            imported,
            failed,
            pulse_count,
            latest_pulse_modified_datetime,
        )

        return self._create_pulse_state(latest_pulse_modified_datetime)
    

    def _get_present_reports(self):
        self.report_cache = []
        query = """
            query Reports($after: ID) {
                reports(first: 5000, after: $after) {
                    edges {
                        node {
                            name
                            published
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }
                }
            }

        """

        reports_list = self.helper.api.query(query, {"after": ""})
        reports = reports_list["data"]["reports"]["edges"]

        while reports_list["data"]["reports"]["pageInfo"]["hasNextPage"]:
            reports_list = self.helper.api.query(query, {"after": reports_list["data"]["reports"]["pageInfo"]["endCursor"]})
            reports += reports_list["data"]["reports"]["edges"]

        for report in reports:
            self.report_cache.append((report["node"]["name"], report["node"]["published"]))

    def _create_pulse_state(self, latest_pulse_timestamp: datetime) -> Dict[str, Any]:
        return {self._LATEST_PULSE_TIMESTAMP: latest_pulse_timestamp.isoformat()}

    def _get_latest_pulse_datetime_from_state(self, state: Dict[str, Any]) -> datetime:
        latest_modified_timestamp = state.get(
            self._LATEST_PULSE_TIMESTAMP, self.default_latest_timestamp
        )
        return iso_datetime_str_to_datetime(latest_modified_timestamp)

    def _clear_malware_guess_cache(self):
        self.malware_guess_cache.clear()

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def _fetch_subscribed_pulses(self, modified_since: datetime) -> List[Pulse]:
        pulses = self.client.get_pulses_subscribed(modified_since)
        return self._sort_pulses(pulses)

    @staticmethod
    def _sort_pulses(pulses: List[Pulse]) -> List[Pulse]:
        def _key_func(pulse: Pulse) -> datetime:
            return pulse.modified

        return sorted(pulses, key=_key_func)

    def _process_pulse(self, pulse: Pulse) -> bool:
        self._info(
            "Processing pulse {0} ({1} indicators) ({2})",
            pulse.name,
            len(pulse.indicators),
            pulse.id,
        )

        pulse_bundle = self._create_pulse_bundle(pulse)
        if pulse_bundle is None:
            return False

        self._send_bundle(pulse_bundle)

        return True

    def _create_pulse_bundle(self, pulse: Pulse) -> Optional[stix2.Bundle]:
        config = PulseBundleBuilderConfig(
            pulse=pulse,
            provider=self.author,
            source_name=self._source_name(),
            object_markings=[self.tlp_marking],
            create_observables=self.create_observables,
            create_indicators=self.create_indicators,
            confidence_level=self._confidence_level(),
            report_status=self.report_status,
            report_type=self.report_type,
            guessed_malwares=self._guess_malwares_from_tags(pulse.tags),
            guessed_cves=self._guess_cves_from_tags(pulse.tags),
            excluded_pulse_indicator_types=self.excluded_pulse_indicator_types,
            enable_relationships=self.enable_relationships,
            enable_attack_patterns_indicates=self.enable_attack_patterns_indicates,
            malware_blacklist=self.malware_blacklist
        )

        bundle_builder = PulseBundleBuilder(config, self.helper, self.report_cache)

        try:
            return bundle_builder.build()
        except STIXError as e:
            self._error(
                "Failed to build pulse bundle for '{0}' ({1}): {2}",
                pulse.name,
                pulse.id,
                e,
            )
            return None

    def _guess_cves_from_tags(self, tags: List[str]) -> Set[str]:
        cves: Set[str] = set()

        if not self.guess_cve:
            return cves

        for tag in tags:
            if not tag:
                continue

            match = self.guess_cve_pattern.search(tag)
            if not match:
                continue

            cve = match.group(1)

            cve = cve.upper()

            cves.add(cve)

        return cves

    def _guess_malwares_from_tags(self, tags: List[str]) -> Mapping[str, str]:
        if not self.guess_malware:
            return {}

        malwares = {}
        for tag in tags:
            if not tag:
                continue

            guess = self.malware_guess_cache.get(tag)
            if guess is None:
                guess = self._GUESS_NOT_A_MALWARE

                standard_id = self._fetch_malware_standard_id_by_name(tag)
                if standard_id is not None:
                    guess = standard_id

                self.malware_guess_cache[tag] = guess

            if guess == self._GUESS_NOT_A_MALWARE:
                self._info("Tag '{0}' does not reference malware", tag)
            else:
                self._info("Tag '{0}' references malware '{1}'", tag, guess)
                malwares[tag] = guess
        return malwares

    def _fetch_malware_standard_id_by_name(self, name: str) -> Optional[str]:
        filters = [
            self._create_filter("name", name),
            self._create_filter("aliases", name),
        ]
        for _filter in filters:
            malwares = self.helper.api.malware.list(filters=_filter)
            if malwares:
                if len(malwares) > 1:
                    self._info("More then one malware for '{0}'", name)
                malware = malwares[0]
                return malware["standard_id"]
        return None

    @staticmethod
    def _create_filter(key: str, value: str) -> List[Mapping[str, Any]]:
        return [{"key": key, "values": [value]}]

    def _source_name(self) -> str:
        return self.helper.connect_name

    def _confidence_level(self) -> int:
        return self.helper.connect_confidence_level

    def _set_state(self, state: Dict[str, Any]) -> None:
        self.helper.set_state(state)

    def _send_bundle(self, bundle: stix2.Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, update=self.update_existing_data, work_id=self.work_id
        )
