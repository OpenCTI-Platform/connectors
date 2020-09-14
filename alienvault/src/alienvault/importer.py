# -*- coding: utf-8 -*-
"""OpenCTI AlienVault importer module."""

import re
from typing import Any, Dict, List, Mapping, Optional, Set

from pycti.connector.opencti_connector_helper import (  # type: ignore
    OpenCTIConnectorHelper,
)

from stix2 import Bundle, Identity, MarkingDefinition  # type: ignore
from stix2.exceptions import STIXError  # type: ignore

from alienvault.builder import PulseBundleBuilder
from alienvault.client import AlienVaultClient
from alienvault.models import Pulse
from alienvault.utils import iso_datetime_str_to_datetime


class PulseImporter:
    """AlienVault pulse importer."""

    _LATEST_PULSE_TIMESTAMP = "latest_pulse_timestamp"

    _GUESS_NOT_A_MALWARE = "GUESS_NOT_A_MALWARE"

    _GUESS_CVE_PATTERN = r"(CVE-\d{4}-\d{4,7})"

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: AlienVaultClient,
        author: Identity,
        tlp_marking: MarkingDefinition,
        create_observables: bool,
        create_indicators: bool,
        update_existing_data: bool,
        default_latest_timestamp: str,
        report_status: int,
        report_type: str,
        guess_malware: bool,
        guess_cve: bool,
    ) -> None:
        """Initialize AlienVault indicator importer."""
        self.helper = helper
        self.client = client
        self.author = author
        self.tlp_marking = tlp_marking
        self.create_observables = create_observables
        self.create_indicators = create_indicators
        self.update_existing_data = update_existing_data
        self.default_latest_timestamp = default_latest_timestamp
        self.report_status = report_status
        self.report_type = report_type
        self.guess_malware = guess_malware
        self.guess_cve = guess_cve

        self.malware_guess_cache: Dict[str, str] = {}
        self.guess_cve_pattern = re.compile(self._GUESS_CVE_PATTERN, re.IGNORECASE)

    def run(self, state: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run importer."""
        self._info(
            "Running pulse importer (update data: {0}, guess malware: {1}, guess cve: {2})...",  # noqa: E501
            self.update_existing_data,
            self.guess_malware,
            self.guess_cve,
        )

        self._clear_malware_guess_cache()

        fetch_timestamp = state.get(
            self._LATEST_PULSE_TIMESTAMP, self.default_latest_timestamp
        )
        fetch_datetime = iso_datetime_str_to_datetime(fetch_timestamp)

        latest_fetched_indicator_datetime = fetch_datetime

        pulses = self.client.get_pulses_subscribed(fetch_datetime)
        pulse_count = len(pulses)

        self._info("{0} pulse(s) since {1}...", pulse_count, fetch_datetime)

        failed = 0
        for pulse in pulses:
            result = self._process_pulse(pulse)
            if not result:
                failed += 1

            if pulse.modified > latest_fetched_indicator_datetime:
                latest_fetched_indicator_datetime = pulse.modified

        state_timestamp = latest_fetched_indicator_datetime

        imported = pulse_count - failed

        self._info(
            "Pulse importer completed (imported: {0}, failed: {1}, total: {2}), latest fetch {3}",  # noqa: E501
            imported,
            failed,
            pulse_count,
            state_timestamp,
        )

        return {self._LATEST_PULSE_TIMESTAMP: state_timestamp.isoformat()}

    def _clear_malware_guess_cache(self):
        self.malware_guess_cache.clear()

    def _info(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_info(fmt_msg)

    def _error(self, msg: str, *args: Any) -> None:
        fmt_msg = msg.format(*args)
        self.helper.log_error(fmt_msg)

    def _process_pulse(self, pulse: Pulse) -> bool:
        self._info("Processing pulse {0} ({1})...", pulse.name, pulse.id)

        pulse_bundle = self._create_pulse_bundle(pulse)
        if pulse_bundle is None:
            return False

        with open(f"bundle_{pulse.id}.json", "w") as f:
            f.write(pulse_bundle.serialize(pretty=True))

        self._send_bundle(pulse_bundle)

        return True

    def _create_pulse_bundle(self, pulse: Pulse) -> Optional[Bundle]:
        author = self.author
        source_name = self._source_name()
        object_marking_refs = [self.tlp_marking]
        create_observables = self.create_observables
        create_indicators = self.create_indicators
        confidence_level = self._confidence_level()
        report_status = self.report_status
        report_type = self.report_type
        guessed_malwares = self._guess_malwares_from_tags(pulse.tags)
        guessed_cves = self._guess_cves_from_tags(pulse.tags)

        bundle_builder = PulseBundleBuilder(
            pulse,
            author,
            source_name,
            object_marking_refs,
            create_observables,
            create_indicators,
            confidence_level,
            report_status,
            report_type,
            guessed_malwares,
            guessed_cves,
        )

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

    def _send_bundle(self, bundle: Bundle) -> None:
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, None, self.update_existing_data, False
        )
