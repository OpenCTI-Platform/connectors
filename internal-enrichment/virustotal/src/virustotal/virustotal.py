"""VirusTotal enrichment connector."""

from typing import TYPE_CHECKING, Dict

import stix2
from pycti import Identity, OpenCTIConnectorHelper
from virustotal.client import VirusTotalClient
from virustotal.models.configs.config_loader import ConfigLoader
from virustotal.processors import (
    FileProcessor,
    HostnameProcessor,
    IPProcessor,
    URLProcessor,
)

if TYPE_CHECKING:
    from virustotal.processors.entity import EntityProcessor


# Maps every supported entity type to its processor class.
_PROCESSOR_MAP: dict[str, "type[EntityProcessor]"] = {
    "StixFile": FileProcessor,
    "Artifact": FileProcessor,
    "IPv4-Addr": IPProcessor,
    "Domain-Name": HostnameProcessor,
    "Hostname": HostnameProcessor,
    "Url": URLProcessor,
}

# Observable type strings as returned by x_opencti_observable_values.type
# (OpenCTI may send PascalCase or lowercase; we normalise to lowercase).
_OBSERVABLE_TYPE_MAP: dict[str, str] = {
    "ipv4-addr": "IPv4-Addr",
    "domain-name": "Domain-Name",
    "hostname": "Hostname",
    "url": "Url",
    "stixfile": "StixFile",
}

# Hash preference order for StixFile VT lookups.
_HASH_PRIORITY: dict[str, int] = {"SHA-256": 0, "SHA-1": 1, "MD5": 2}


class VirusTotalConnector:
    """VirusTotal enrichment connector."""

    _SOURCE_NAME = "VirusTotal"
    _API_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):
        # Instantiate the connector helper from config
        self.config = config
        self.helper = helper

        self.author = stix2.Identity(
            id=Identity.generate_id(self._SOURCE_NAME, "organization"),
            name=self._SOURCE_NAME,
            identity_class="organization",
            description="VirusTotal",
            confidence=self.helper.connect_confidence_level,
        )

        self.max_tlp = self.config.virustotal.max_tlp
        self.replace_with_lower_score = self.config.virustotal.replace_with_lower_score
        token = self.config.virustotal.token.get_secret_value()
        self.client = VirusTotalClient(self.helper, self._API_URL, token)

        # Cache to store YARA rulesets.
        self.yara_cache = {}

        # File/Artifact specific settings
        self.file_create_note_full_report = (
            self.config.virustotal.file_create_note_full_report
        )
        self.file_import_yara = self.config.virustotal.file_import_yara
        self.file_upload_unseen_artifacts = (
            self.config.virustotal.file_upload_unseen_artifacts
        )
        self.file_indicator_config = self.config.virustotal.model_extra.get(
            "file_indicator_config"
        )

        # IP specific settings
        self.ip_add_relationships = self.config.virustotal.ip_add_relationships
        self.ip_indicator_config = self.config.virustotal.model_extra.get(
            "ip_indicator_config"
        )

        # Domain specific settings
        self.domain_add_relationships = self.config.virustotal.domain_add_relationships
        self.domain_indicator_config = self.config.virustotal.model_extra.get(
            "domain_indicator_config"
        )

        # Url specific settings
        self.url_upload_unseen = self.config.virustotal.url_upload_unseen
        self.url_indicator_config = self.config.virustotal.model_extra.get(
            "url_indicator_config"
        )

        # Generic config settings for File, IP, Domain, URL
        self.include_attributes_in_note = (
            self.config.virustotal.include_attributes_in_note
        )

    # ------------------------------------------------------------------
    # YARA cache (shared across processor instances)
    # ------------------------------------------------------------------

    def _retrieve_yara_ruleset(self, ruleset_id: str) -> dict:
        """Return the YARA ruleset, fetching from the API if not cached."""
        self.helper.log_debug(f"[VirusTotal] Retrieving ruleset {ruleset_id}")
        if ruleset_id not in self.yara_cache:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from API.")
            self.yara_cache[ruleset_id] = self.client.get_yara_ruleset(ruleset_id)
        else:
            self.helper.log_debug(f"Retrieving YARA ruleset {ruleset_id} from cache.")
        return self.yara_cache[ruleset_id]

    # ------------------------------------------------------------------
    # Indicator helpers
    # ------------------------------------------------------------------

    def _extract_observable_from_indicator(
        self, opencti_entity: dict
    ) -> list[tuple[str, str]]:
        """Extract all supported observable (type, value) pairs from an Indicator.

        An indicator's pattern can embed several observables — for example
        ``[ipv4-addr:value = '1.2.3.4' AND domain-name:value = 'evil.com']``
        produces two entries in ``x_opencti_observable_values``.  This method
        returns **all** supported pairs so the caller can enrich each one.

        Uses the ``x_opencti_observable_values`` extension attribute populated
        by OpenCTI. For ``StixFile``, the best available hash is returned
        (SHA-256 > SHA-1 > MD5) rather than the raw ``value`` field.

        Returns
        -------
        list[tuple[str, str]]
            Ordered list of ``(entity_type, observable_value)`` pairs,
            e.g. ``[("IPv4-Addr", "1.2.3.4"), ("Domain-Name", "evil.com")]``.

        Raises
        ------
        ValueError
            When no supported observable can be extracted from the indicator.
        """
        observable_values = self.helper.get_attribute_in_extension(
            "x_opencti_observable_values", opencti_entity
        )
        if not observable_values:
            raise ValueError(
                "[VirusTotal] Cannot enrich Indicator: no observable values found. "
                "Ensure the indicator has a valid STIX pattern."
            )

        results: list[tuple[str, str]] = []
        for obs in observable_values:
            entity_type = _OBSERVABLE_TYPE_MAP.get(obs.get("type", "").lower())
            if not entity_type:
                continue

            value = (
                self._best_hash_from_obs(obs)
                if entity_type == "StixFile"
                else obs.get("value")
            )
            if value:
                results.append((entity_type, value))

        if not results:
            raise ValueError(
                f"[VirusTotal] Cannot enrich Indicator: none of the observable types "
                f"{[o.get('type') for o in observable_values]} are supported. "
                f"Supported types: {', '.join(_PROCESSOR_MAP)}."
            )

        return results

    @staticmethod
    def _best_hash_from_obs(obs: dict) -> str:
        """Return the highest-priority hash from an observable dict."""
        best_hash: str = ""
        best_priority = 999
        for h in obs.get("hashes", []):
            priority = _HASH_PRIORITY.get(h.get("algorithm", ""), 999)
            if priority < best_priority:
                best_priority = priority
                best_hash = h.get("hash", "")
        return best_hash or obs.get("value", "")

    # ------------------------------------------------------------------
    # Processor factory & message handler
    # ------------------------------------------------------------------

    def _get_processor(
        self,
        entity_type: str,
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        is_indicator: bool = False,
    ) -> "EntityProcessor":
        """Instantiate the correct processor for *entity_type*."""
        cls = _PROCESSOR_MAP.get(entity_type)
        if cls is None:
            raise ValueError(f"{entity_type} is not a supported entity type.")
        return cls(self, stix_objects, stix_entity, opencti_entity, is_indicator)

    def _process_message(self, data: Dict) -> str:
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        # TLP gate
        tlp = "TLP:CLEAR"
        for marking in opencti_entity.get("objectMarking", []):
            if marking["definition_type"] == "TLP":
                tlp = marking["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        entity_type = opencti_entity["entity_type"]
        is_indicator = entity_type == "Indicator"

        if is_indicator:
            observables = self._extract_observable_from_indicator(opencti_entity)
            object_markings = opencti_entity.get("objectMarking", [])
            self.helper.log_debug(
                f"[VirusTotal] enriching indicator "
                f"'{opencti_entity.get('name', '?')}' "
                f"with {len(observables)} observable(s): "
                f"{observables}"
            )
            results = []
            for obs_type, observable_value in observables:
                # Build a synthetic entity that looks like an observable so
                # processors can access observable_value and entity_type uniformly.
                synthetic_entity = {
                    "entity_type": obs_type,
                    "observable_value": observable_value,
                    "objectMarking": object_markings,
                }
                result = self._get_processor(
                    obs_type, stix_objects, stix_entity, synthetic_entity, True
                ).process()
                results.append(result)
            return "; ".join(r for r in results if r is not None)

        self.helper.log_debug(
            f"[VirusTotal] enriching observable: "
            f"{opencti_entity.get('observable_value', '?')}"
        )

        return self._get_processor(
            entity_type, stix_objects, stix_entity, opencti_entity, False
        ).process()

    def start(self) -> None:
        """Start the main listener loop."""
        self.helper.metric.state("idle")
        self.helper.listen(message_callback=self._process_message)
