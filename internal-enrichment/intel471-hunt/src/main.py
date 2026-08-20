"""OpenCTI Internal Enrichment connector: Intel 471 Hunter."""

from __future__ import annotations

import logging
from typing import Any

import stix2
from pycti import OpenCTIConnectorHelper

from . import entity_mapper, stix_builder
from .cache import HuntCache
from .config import load_config
from .hunter_client import HunterClient

LOGGER = logging.getLogger(__name__)


class HunterEnrichmentConnector:
    def __init__(self) -> None:
        config = load_config()
        self.helper = OpenCTIConnectorHelper(config.raw)
        self.client = HunterClient(
            api_base_url=config.hunter.api_base_url,
            api_key=config.hunter.api_key,
            indexes=config.hunter.indexes,
            timeout_seconds=config.hunter.request_timeout_seconds,
            max_results=config.hunter.max_results_per_query,
        )
        self.cache = HuntCache(
            config.hunter.cache_path, ttl_hours=config.hunter.cache_ttl_hours
        )
        self.author = stix_builder.build_author()
        self.confidence = config.default_confidence
        self.hunter_ui_base_url = config.hunter.ui_base_url

    # ------------------------------------------------------------------
    # Connector wiring
    # ------------------------------------------------------------------

    def start(self) -> None:
        self.helper.listen(message_callback=self._process_message)

    def _process_message(self, data: dict[str, Any]) -> str:
        entity = self._resolve_entity(data)
        if not entity:
            return "Could not resolve enrichment entity"

        queries = entity_mapper.build_query(entity)
        if not queries:
            return (
                f"Entity type {entity.get('entity_type')!r} not in scope; nothing to do"
            )

        self.helper.log_info(f"Hunter queries for {entity.get('name')}: {queries}")
        hunts_by_uuid: dict[str, dict[str, Any]] = {}
        for q in queries:
            for h in self.client.query(**q):
                key = (h.get("UUID") or h.get("uuid") or h.get("id") or "").lower()
                if key:
                    hunts_by_uuid[key] = h
        hunts = list(hunts_by_uuid.values())
        if not hunts:
            return f"Hunter returned no hunts for {entity.get('name')!r}"

        trigger_entity = self._trigger_payload(entity)

        objects: list[Any] = [self.author]
        skipped = 0
        pushed_uuids: list[tuple[str, str]] = []
        for hunt in hunts:
            uuid_val = hunt.get("UUID") or hunt.get("uuid") or hunt.get("id") or ""
            last_updated = hunt.get("last_updated") or ""
            if uuid_val and self.cache.is_fresh(uuid_val, last_updated):
                skipped += 1
                continue
            built = stix_builder.build_bundle(
                hunt,
                self.author,
                confidence=self.confidence,
                hunter_ui_base_url=self.hunter_ui_base_url,
                trigger_entity=trigger_entity,
            )
            if built:
                objects.extend(built)
                pushed_uuids.append((uuid_val, last_updated))

        if len(objects) == 1:
            return f"All {len(hunts)} hunts already cached; nothing to push"

        bundle = stix2.Bundle(objects=objects, allow_custom=True).serialize()
        bundles_sent = self.helper.send_stix2_bundle(bundle, update=True)
        for uuid_val, last_updated in pushed_uuids:
            self.cache.mark(uuid_val, last_updated)

        return (
            f"Pushed {len(objects) - 1} STIX objects from {len(pushed_uuids)} hunts "
            f"({skipped} cached) — {len(bundles_sent)} bundles sent"
        )

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

    def _resolve_entity(self, data: dict[str, Any]) -> dict[str, Any] | None:
        if isinstance(data.get("enrichment_entity"), dict):
            return data["enrichment_entity"]
        entity_id = (
            data.get("entity_id")
            or data.get("standard_id")
            or (data.get("entity") or {}).get("standard_id")
        )
        if not entity_id:
            return None
        try:
            return self.helper.api.stix_domain_object.read(id=entity_id)
        except Exception as exc:  # pragma: no cover - depends on live OpenCTI
            self.helper.log_error(f"Failed to read entity {entity_id}: {exc}")
            return None


def main() -> None:  # pragma: no cover - entrypoint
    HunterEnrichmentConnector().start()


if __name__ == "__main__":  # pragma: no cover
    main()
