from connector.converter_to_stix import ConverterToStix, tag_names
from connector.event_filter import EventFilter
from connector.misp_client import MispClient, MispMatch
from connector.pattern_extractor import extract_values_from_pattern
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

# STIX observable types whose `value` is looked up in MISP
_VALUE_OBSERVABLE_TYPES = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"}
_HASH_ALGORITHMS = ("SHA-256", "SHA-1", "MD5", "SHA-512")


class MispEnrichmentConnector:
    """
    Internal enrichment connector looking up observables and STIX indicators in MISP.

    For each enrichment:
      1. The values to look up are taken from the observable (every hash for a file)
         or extracted from the STIX pattern of the indicator.
      2. MISP attributes matching these values are searched, then their events are retrieved.
      3. Events rejected by the configured event filters are dropped.
      4. The entity is sent back with one external reference per event and, depending on
         the configuration, the attribute and event tags as labels, along with one Note
         per event and, optionally, one Report per event.

    To be compatible with playbooks, every code path that does not raise sends a bundle
    containing the entity.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        misp_url = str(self.config.misp.url).rstrip("/")
        self.client = MispClient(
            url=misp_url,
            api_key=self.config.misp.api_key.get_secret_value(),
            ssl_verify=self.config.misp.ssl_verify,
        )
        self.event_filter = EventFilter(self.config.misp)
        self.converter_to_stix = ConverterToStix(
            misp_url=misp_url,
            attribute_comment_filter_regex=self.config.misp.attribute_comment_filter_regex,
        )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def process_message(self, data: dict) -> str:
        opencti_entity: dict = data["enrichment_entity"]
        stix_entity: dict = data["stix_entity"]
        stix_objects: list = data["stix_objects"]
        # Messages coming from a playbook have no event type
        is_playbook = not data.get("event_type")

        if not self._entity_in_scope(opencti_entity):
            if is_playbook:
                return self._send_bundle(stix_objects)
            raise ValueError(
                f"Failed to process entity, {opencti_entity['entity_type']} is not a supported entity type."
            )

        if not self._is_tlp_allowed(opencti_entity):
            if is_playbook:
                return self._skip(
                    "TLP of the entity is greater than MAX TLP, skipping",
                    stix_objects,
                    is_playbook,
                )
            raise ValueError(
                "TLP of the entity is greater than MAX TLP, the entity is not sent to MISP."
            )

        values = self._values_to_look_up(stix_entity)
        if not values:
            return self._skip(
                "No value to look up in MISP, skipping", stix_objects, is_playbook
            )

        self.helper.connector_logger.info(
            "[MISP] Looking up values",
            {"entity_id": stix_entity["id"], "values": values},
        )
        matches = self.client.search(values)
        retained = [
            match for match in matches if self.event_filter.accepts(match.event)
        ]
        self.helper.connector_logger.info(
            "[MISP] Events found",
            {"found": len(matches), "retained_after_filters": len(retained)},
        )
        if not retained:
            return self._skip("No MISP event found", stix_objects, is_playbook)

        enrichment = self._build_enrichment(stix_entity, retained, values)
        return self._send_bundle(
            [obj for obj in stix_objects if obj.get("id") != stix_entity["id"]]
            + enrichment
        )

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def _build_enrichment(
        self, stix_entity: dict, matches: list[MispMatch], values: list[str]
    ) -> list:
        """Return the enriched entity followed by the author, the Notes and the Reports."""
        entity_id = stix_entity["id"]
        markings = stix_entity.get("object_marking_refs", [])

        labels: list[str] = []
        for match in matches:
            if self.config.misp.import_attribute_tags_as_labels:
                for attribute in match.attributes:
                    labels.extend(tag_names(attribute.get("Tag")))
            if self.config.misp.import_associated_events_tags_as_labels:
                labels.extend(tag_names(match.event.get("Tag")))
        labels = list(dict.fromkeys(labels))

        objects: list = [
            self.converter_to_stix.enrich_entity(stix_entity, matches, labels),
            self.converter_to_stix.author,
        ]
        for match in matches:
            objects.append(
                self.converter_to_stix.create_note(
                    match, self._matched_values(match, values), entity_id, markings
                )
            )
            if self.config.misp.import_events:
                objects.append(
                    self.converter_to_stix.create_report(match, entity_id, markings)
                )
        return objects

    @staticmethod
    def _matched_values(match: MispMatch, values: list[str]) -> list[str]:
        """The looked-up values found in the attributes of a match (composite values included)."""
        found: set[str] = set()
        for attribute in match.attributes:
            attribute_value = str(attribute.get("value") or "")
            found.add(attribute_value.lower())
            found.update(part.lower() for part in attribute_value.split("|"))
        return [value for value in values if value.lower() in found] or values

    @staticmethod
    def _values_to_look_up(stix_entity: dict) -> list[str]:
        entity_type = stix_entity.get("type", "").lower()
        if entity_type in _VALUE_OBSERVABLE_TYPES:
            value = (stix_entity.get("value") or "").strip()
            return [value] if value else []
        if entity_type == "file":
            hashes: dict = stix_entity.get("hashes") or {}
            return list(
                dict.fromkeys(
                    hashes[algorithm].strip()
                    for algorithm in _HASH_ALGORITHMS
                    if (hashes.get(algorithm) or "").strip()
                )
            )
        if entity_type == "indicator" and stix_entity.get("pattern_type") == "stix":
            return extract_values_from_pattern(stix_entity.get("pattern") or "")
        return []

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _entity_in_scope(self, opencti_entity: dict) -> bool:
        scopes = [
            scope.strip().lower() for scope in self.helper.connect_scope.split(",")
        ]
        return opencti_entity["entity_type"].lower() in scopes

    def _is_tlp_allowed(self, opencti_entity: dict) -> bool:
        tlp = None
        for marking in opencti_entity.get("objectMarking", []):
            if marking.get("definition_type") == "TLP":
                tlp = marking["definition"]
        return self.helper.check_max_tlp(
            tlp, f"TLP:{self.config.connector.max_tlp.upper()}"
        )

    # ------------------------------------------------------------------
    # Bundle
    # ------------------------------------------------------------------

    def _skip(self, message: str, stix_objects: list, is_playbook: bool) -> str:
        """Stop the enrichment; in a playbook, send the original bundle so that it continues."""
        self.helper.connector_logger.info(
            "[MISP] Enrichment skipped", {"reason": message}
        )
        if is_playbook:
            self._send_bundle(stix_objects)
        return message

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            stix_objects_bundle, cleanup_inconsistent_bundle=True
        )
        return f"Sending {len(bundles_sent)} STIX bundle(s) for worker import"

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
