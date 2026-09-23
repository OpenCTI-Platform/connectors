"""OpenCTI internal enrichment connector: Intel 471 Hunter."""

from __future__ import annotations

from typing import Any

from pycti import OpenCTIConnectorHelper
from src import entity_mapper, stix_builder
from src.cache import HuntCache
from src.hunter_client import HunterClient
from src.settings import ConnectorSettings


class HunterEnrichmentConnector:
    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper
        self.client = HunterClient(
            api_base_url=str(config.hunter.api_base_url),
            api_key=config.hunter.api_key.get_secret_value(),
            indexes=config.hunter.indexes,
            timeout_seconds=config.hunter.request_timeout_seconds,
            max_results=config.hunter.max_results_per_query,
        )
        self.cache = HuntCache(
            config.hunter.cache_path, ttl_hours=config.hunter.cache_ttl_hours
        )
        self.author = stix_builder.build_author()
        self.hunter_ui_base_url = (
            str(config.hunter.ui_base_url) if config.hunter.ui_base_url else None
        )

    # ------------------------------------------------------------------
    # Connector wiring
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)

    def _send_bundle(self, objects: list[Any]) -> list[str]:
        # `stix2_create_bundle` serialises our own STIX objects but passes the
        # platform's dicts through untouched — unlike `stix2.Bundle`, which
        # would re-validate the incoming bundle and could reject it.
        bundle = self.helper.stix2_create_bundle(list(objects))
        return self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)

    @staticmethod
    def _is_playbook_run(data: dict[str, Any]) -> bool:
        """Playbook steps arrive without an ``event_type``; a manual enrichment
        carries one. Only a playbook needs the original bundle handed back, so
        the step that follows still has something to work on."""
        return not data.get("event_type")

    def _return_original(self, stix_objects: list[Any], data: dict[str, Any]) -> None:
        """Hand the incoming bundle back unchanged when we produce nothing."""
        if self._is_playbook_run(data):
            self._send_bundle(stix_objects)

    def _check_max_tlp(self, opencti_entity: dict[str, Any]) -> None:
        """Refuse to enrich an entity whose TLP exceeds the configured maximum."""
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking") or []:
            if marking_definition.get("definition_type") == "TLP":
                tlp = marking_definition["definition"]
        max_tlp = self.config.hunter.max_tlp
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, max_tlp):
            raise ValueError(
                f"Do not send any data, TLP of the entity ({tlp}) is greater "
                f"than MAX TLP ({max_tlp})"
            )

    def process_message(self, data: dict[str, Any]) -> str:
        # The original bundle is returned unchanged whenever we produce nothing,
        # so playbook runs continue past this step.
        stix_objects = data["stix_objects"] if "stix_objects" in data else []
        try:
            entity = data.get("enrichment_entity")
            if not isinstance(entity, dict):
                self._return_original(stix_objects, data)
                return "No enrichment entity in message; nothing to do"

            self._check_max_tlp(entity)

            queries = entity_mapper.build_query(entity)
            if not queries:
                self._return_original(stix_objects, data)
                return (
                    f"Entity type {entity.get('entity_type')!r} not in scope; "
                    "nothing to do"
                )

            self.helper.connector_logger.info(
                "[INTEL471 HUNTER] Querying Hunter",
                {"entity_name": entity.get("name"), "queries": queries},
            )
            hunts = self._fetch_hunts(queries)
            if not hunts:
                self._return_original(stix_objects, data)
                return f"Hunter returned no hunts for {entity.get('name')!r}"

            markings = self._markings_from_entity(data.get("stix_entity") or {})
            trigger_entity = self._trigger_payload(entity)

            objects: list[Any] = [self.author]
            skipped = 0
            pushed_uuids: list[tuple[str, str]] = []
            for hunt in hunts:
                uuid_val = self._hunt_uuid(hunt)
                last_updated = hunt.get("last_updated") or ""
                if uuid_val and self.cache.is_fresh(uuid_val, last_updated):
                    skipped += 1
                    continue
                built = stix_builder.build_bundle(
                    hunt,
                    self.author,
                    hunter_ui_base_url=self.hunter_ui_base_url,
                    trigger_entity=trigger_entity,
                    markings=markings,
                )
                if built:
                    objects.extend(built)
                    pushed_uuids.append((uuid_val, last_updated))

            if len(objects) == 1:
                self._return_original(stix_objects, data)
                return f"All {len(hunts)} hunts already cached; nothing to push"

            bundles_sent = self._send_bundle(stix_objects + objects)
            for uuid_val, last_updated in pushed_uuids:
                self.cache.mark(uuid_val, last_updated)

            self.helper.connector_logger.info(
                "[INTEL471 HUNTER] Enrichment complete",
                {
                    "hunts_pushed": len(pushed_uuids),
                    "hunts_cached": skipped,
                    "bundles_sent": len(bundles_sent),
                },
            )
            return (
                f"Pushed {len(objects) - 1} STIX objects from {len(pushed_uuids)} "
                f"hunts ({skipped} cached) — {len(bundles_sent)} bundles sent"
            )
        except Exception as err:
            # Always hand the original bundle back so playbooks keep flowing.
            self._send_bundle(stix_objects)
            self.helper.connector_logger.error(
                "[INTEL471 HUNTER] Unexpected error",
                {"error_message": str(err)},
            )
            return f"Error: {err}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fetch_hunts(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Run every query and union the results by hunt UUID (Location triggers
        fan out to a target_* and a source_* call)."""
        hunts_by_uuid: dict[str, dict[str, Any]] = {}
        for query in queries:
            for hunt in self.client.query(**query):
                key = self._hunt_uuid(hunt)
                if key:
                    hunts_by_uuid[key] = hunt
        return list(hunts_by_uuid.values())

    @staticmethod
    def _hunt_uuid(hunt: dict[str, Any]) -> str:
        return (hunt.get("UUID") or hunt.get("uuid") or hunt.get("id") or "").lower()

    @staticmethod
    def _markings_from_entity(stix_entity: dict[str, Any]) -> list[str] | None:
        """Propagate the triggering entity's markings onto what we create."""
        marking_refs = stix_entity.get("object_marking_refs") or []
        return list(marking_refs) or None

    @staticmethod
    def _trigger_payload(entity: dict[str, Any]) -> dict[str, Any]:
        stix_id = entity.get("standard_id") or ""
        if "--" not in stix_id:
            raw_id = entity.get("id") or ""
            stix_id = raw_id if "--" in raw_id else ""
        mitre_id = entity.get("x_mitre_id") or entity.get("x_opencti_external_id") or ""
        if not mitre_id:
            for ref in entity.get("external_references") or []:
                if ref.get("source_name", "").lower().startswith("mitre"):
                    mitre_id = ref.get("external_id") or ""
                    if mitre_id:
                        break
        return {
            "id": stix_id,
            "type": entity.get("entity_type") or entity.get("type") or "",
            "name": entity.get("name") or "",
            "x_mitre_id": mitre_id,
        }
