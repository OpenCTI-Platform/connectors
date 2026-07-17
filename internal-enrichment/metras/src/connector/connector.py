"""Metras Enrichment connector (INTERNAL_ENRICHMENT).

Answers "have I seen this in my fleet?" for IPv4-Addr / file-hash observables by
querying Metras, returning context Notes + System-identity links.
"""

from collections.abc import Callable
from typing import Any

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.utils import refang
from metras_client import MetrasAPIError, MetrasClient
from pycti import OpenCTIConnectorHelper


class MetrasEnrichmentConnector:

    # TLP levels by restrictiveness (keyed on connectors_sdk TLPLevel values).
    _LEVEL_ORDER = {
        "clear": 0,
        "white": 0,
        "green": 1,
        "amber": 2,
        "amber+strict": 3,
        "red": 4,
    }
    _MARKING_TO_LEVEL = {
        "marking-definition--613f2e26-407d-48c7-9eba-b56c171b6f0c": "white",
        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
        "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37": "amber+strict",
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
    }
    # OpenCTI scope names vs STIX SCO type names that differ.
    _SCOPE_ALIASES = {"file": "stixfile"}

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper
        cfg = config.metras
        self.client = MetrasClient(
            helper=helper,
            base_url=str(cfg.api_base_url),
            api_key=cfg.api_key.get_secret_value(),
            verify_ssl=cfg.verify_ssl,
        )
        self.converter = ConverterToStix(helper)
        self._max_tlp = cfg.max_tlp  # connectors_sdk TLPLevel enum
        self._errors = []
        self._successes = 0

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        try:
            self.client.ping()
            self.helper.connector_logger.info(
                "[CONNECTOR] Metras API connection verified"
            )
        except MetrasAPIError as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] Metras API ping failed at startup", {"error": str(exc)}
            )
            # Listener still starts so the connector registers; per-message calls
            # will surface auth errors clearly to the analyst.
        self.helper.listen(message_callback=self.process_message)

    # --- Scope + TLP helpers (custom — never helper.check_max_tlp) ---
    def entity_in_scope(self, stix_type: str) -> bool:
        scopes = [s.lower() for s in self.config.connector.scope]
        entity_type = self._SCOPE_ALIASES.get(stix_type.lower(), stix_type.lower())
        return entity_type in scopes

    def _get_tlp_level(self, stix_entity) -> str | None:
        """Return the most restrictive TLP level (lowercase) on the entity, or None."""
        markings = (stix_entity or {}).get("object_marking_refs") or []
        highest, result = -1, None
        for m in markings:
            mid = m if isinstance(m, str) else m.get("standard_id", m.get("id", ""))
            level = self._MARKING_TO_LEVEL.get(mid)
            if level and self._LEVEL_ORDER.get(level, -1) > highest:
                highest = self._LEVEL_ORDER[level]
                result = level
        return result

    def _tlp_allowed(self, level: str) -> bool:
        max_level = self._max_tlp.value  # TLPLevel enum -> lowercase value
        return self._LEVEL_ORDER.get(level, 0) <= self._LEVEL_ORDER.get(max_level, 4)

    def _safe(self, func: Callable, *args, **kwargs) -> Any:
        try:
            result = func(*args, **kwargs)
            self._successes += 1
            return result
        except Exception as exc:  # noqa: BLE001
            self.helper.connector_logger.error(
                f"[CONNECTOR] {getattr(func, '__name__', 'call')} failed",
                {"error": str(exc)},
            )
            self._errors.append(str(exc))
            return None

    # ------------------------------------------------------------------ #
    @staticmethod
    def _resolve_stix_id(data, stix_entity) -> str | None:
        """Resolve the enriched entity's STIX id: standard_id, then the stix_entity id.

        Never the internal OpenCTI database id (not a valid STIX reference — would
        produce inconsistent object_refs/relationships).
        """
        enrichment_entity = data.get("enrichment_entity") or {}
        return enrichment_entity.get("standard_id") or stix_entity.get("id")

    def process_message(self, data: dict) -> str | None:
        try:
            stix_entity = data.get("stix_entity") or {}
            stix_objects = data.get("stix_objects", [])
            obs_type = (stix_entity.get("type") or "").lower()
            obs_id = self._resolve_stix_id(data, stix_entity)
            if not obs_id:
                raise ValueError(
                    "[CONNECTOR] Could not resolve a STIX id for the entity "
                    "(no standard_id or stix_entity id); aborting."
                )

            level = self._get_tlp_level(stix_entity)
            if level and not self._tlp_allowed(level):
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Skipped: TLP exceeds max",
                    {"tlp": level, "max": self._max_tlp.value},
                )
                return f"[CONNECTOR] Skipped: TLP {level} exceeds max {self._max_tlp.value}"

            if not self.entity_in_scope(obs_type):
                return f"[CONNECTOR] {obs_type} not in scope"

            self._errors, self._successes = [], 0
            handlers = {
                "ipv4-addr": self._enrich_ipv4,
                "stixfile": self._enrich_file,
                "file": self._enrich_file,
            }
            handler = handlers.get(obs_type)
            if not handler:
                return f"[CONNECTOR] Unsupported type {obs_type}"

            new_objects = handler(stix_entity, obs_id)

            if self._successes == 0 and self._errors:
                first = self._errors[0]
                raise ValueError(f"[CONNECTOR] All Metras lookups failed: {first}")

            if new_objects:
                bundle_objects = (
                    stix_objects + [self.converter.author_object()] + new_objects
                )
                bundle = self.helper.stix2_create_bundle(bundle_objects)
                sent = self.helper.send_stix2_bundle(
                    bundle, cleanup_inconsistent_bundle=True
                )
                return f"[CONNECTOR] Sent {len(sent)} bundle(s)"
            return "[CONNECTOR] No Metras fleet data found for this observable"
        except Exception as err:  # noqa: BLE001
            self.helper.connector_logger.error("[CONNECTOR] Error", {"error": str(err)})
            raise

    # ------------------------------------------------------------------ #
    def _enrich_ipv4(self, stix_entity: dict, obs_id: str) -> list:
        ip = refang(stix_entity.get("value", ""))
        objects = []
        hits = 0
        notes = []

        alerts = self._safe(self.client.alerts_by_agent_ip, ip) or {}
        alert_data = alerts.get("data") or []
        if alert_data:
            hits += len(alert_data)
            names = ", ".join(
                sorted({a.get("alert_name", "?") for a in alert_data})[:10]
            )
            notes.append(f"EDR alerts where agent_ip={ip}: {len(alert_data)} ({names})")

        eps = self._safe(self.client.list_endpoints, interface_ip=ip) or {}
        endpoints = eps.get("endpoints") or []
        for ep in endpoints:
            system = self.converter.create_system(
                ep.get("name"),
                description=f"Metras endpoint (os={ep.get('os', 'n/a')})",
            )
            if system:
                objects.append(system)
                objects.append(
                    self.converter.create_relationship(
                        obs_id, "related-to", system["id"]
                    )
                )
        if endpoints:
            notes.append(
                f"Matches {len(endpoints)} fleet endpoint(s): "
                + ", ".join(e.get("name", "?") for e in endpoints[:10])
            )

        if notes:
            header = (
                f"Metras fleet hits: {hits} event(s), {len(endpoints)} endpoint(s)."
            )
            objects.append(
                self.converter.create_note(
                    obs_id,
                    "Metras fleet context",
                    header + "\n" + "\n".join(notes),
                    labels=["metras"],
                )
            )
        return objects

    def _enrich_file(self, stix_entity: dict, obs_id: str) -> list:
        hashes = stix_entity.get("hashes") or {}
        sha256 = hashes.get("SHA-256") or hashes.get("SHA256")
        sha1 = hashes.get("SHA-1") or hashes.get("SHA1")
        md5 = hashes.get("MD5")
        objects = []
        binary = None

        if sha256 or sha1:
            res = self._safe(self.client.binary_by_hash, sha256=sha256, sha1=sha1) or {}
            data = res.get("data") or []
            binary = data[0] if data else None
        if binary is None and md5:
            res = self._safe(self.client.binary_details, md5=md5) or {}
            data = res.get("data") or []
            binary = data[0] if data else (res if res.get("md5") else None)

        if not binary:
            return objects

        first_seen = binary.get("first_seen")
        last_seen = binary.get("last_seen")
        content = "\n".join(
            [
                f"Name: {binary.get('name', 'n/a')}",
                f"Publisher: {binary.get('publisher', 'n/a')}",
                f"Signer: {binary.get('signer', 'n/a')}",
                f"Signature: {binary.get('signature_status', 'n/a')}",
                f"Runnability: {binary.get('runnability_status', 'n/a')}",
                f"First seen: {first_seen or 'n/a'}",
                f"Last seen: {last_seen or 'n/a'}",
                f"First endpoint: {binary.get('first_endpoint_name', 'n/a')}",
            ]
        )
        objects.append(
            self.converter.create_note(
                obs_id, "Metras binary inventory", content, labels=["metras"]
            )
        )
        ep = binary.get("first_endpoint_name")
        if ep:
            system = self.converter.create_system(ep, description="Metras endpoint")
            if system:
                objects.append(system)
                objects.append(
                    self.converter.create_relationship(
                        obs_id, "related-to", system["id"]
                    )
                )
        return objects
