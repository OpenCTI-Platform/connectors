import asyncio
import json
from typing import Any

from pycti import OpenCTIConnectorHelper, StixCoreRelationship
from src import ConfigLoader
from src.services import CVEConverter
from src.services.utils import extract_cves_from_entity

CONTAINER_STIX_TYPES = {
    "report",
    "grouping",
    "note",
    "observed-data",
    "opinion",
    "case-incident",
    "x-opencti-case-incident",
    "case-rfi",
    "x-opencti-case-rfi",
    "case-rft",
    "x-opencti-case-rft",
    "task",
    "x-opencti-task",
    "feedback",
    "x-opencti-feedback",
}

# Standard STIX 2.1 TLP marking-definition IDs to canonical TLP names
STIX_TLP_MARKING_DEFINITIONS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:WHITE",
    "marking-definition--clear": "TLP:CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37": "TLP:AMBER+STRICT",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
}


class CVEConnector:
    """NIST NVD CVE Internal Enrichment Connector.

    Listens for Container entities (Report, Case-Incident, Note, Grouping, etc.),
    Incidents, and Vulnerability entities ingested or enriched in OpenCTI.
    Extracts CVE identifiers matching the CVE naming pattern from the entity's
    `name`, `description`, and `content`, queries the NIST NVD API 2.0 to create
    or update the corresponding `Vulnerability` STIX objects (with CVSS v2/v3.0/v3.1/v4.0,
    SSVC, CWEs, references, and optional CPE Software), and links them back to
    the triggering container/entity.
    """

    def __init__(self):
        """Initialize the CVEConnector with necessary configurations."""
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(
            config=self.config.model_dump_pycti(),
            playbook_compatible=True,
        )
        self.converter = CVEConverter(self.helper, self.config)
        self.max_tlp = self._normalize_tlp(self.config.connector.max_tlp)

    @staticmethod
    def _normalize_tlp(tlp_value: str) -> str:
        tlp_upper = tlp_value.upper().strip()
        if not tlp_upper.startswith("TLP:"):
            return f"TLP:{tlp_upper}"
        return tlp_upper

    @staticmethod
    def _extract_tlps(
        enrichment_entity: dict[str, Any],
        stix_entity: dict[str, Any] | None = None,
        stix_objects: list[dict[str, Any]] | None = None,
    ) -> list[str]:
        """Extract all TLP markings from both GraphQL `enrichment_entity` and STIX `object_marking_refs`."""
        tlps: list[str] = []

        for marking in enrichment_entity.get("objectMarking") or []:
            if isinstance(marking, dict) and marking.get("definition_type") == "TLP":
                defn = marking.get("definition")
                if isinstance(defn, str) and defn.strip():
                    tlps.append(defn.strip().upper())

        if stix_entity:
            marking_refs = set(stix_entity.get("object_marking_refs") or [])
            # Check known STIX TLP marking-definition IDs
            for ref in marking_refs:
                if ref in STIX_TLP_MARKING_DEFINITIONS:
                    tlps.append(STIX_TLP_MARKING_DEFINITIONS[ref])
            # Also check any marking-definition objects included in stix_objects
            for obj in stix_objects or []:
                if (
                    isinstance(obj, dict)
                    and obj.get("type") == "marking-definition"
                    and obj.get("id") in marking_refs
                ):
                    defn_type = (obj.get("definition_type") or "").upper()
                    name = (obj.get("name") or "").upper()
                    tlp_val = (obj.get("definition") or {}).get("tlp", "")
                    if name.startswith("TLP:"):
                        tlps.append(name)
                    elif defn_type == "TLP" and tlp_val:
                        tlps.append(f"TLP:{tlp_val.upper()}")

        return tlps or ["TLP:CLEAR"]

    def _check_entity_tlp(
        self,
        enrichment_entity: dict[str, Any],
        stix_entity: dict[str, Any] | None = None,
        stix_objects: list[dict[str, Any]] | None = None,
    ) -> tuple[bool, str]:
        """Ensure every TLP marking on the entity is within `self.max_tlp`."""
        tlps = self._extract_tlps(enrichment_entity, stix_entity, stix_objects)
        for tlp in tlps:
            if not self.helper.check_max_tlp(tlp, self.max_tlp):
                return False, tlp
        return True, tlps[0]

    def _is_in_scope(
        self, stix_entity: dict[str, Any], enrichment_entity: dict[str, Any]
    ) -> bool:
        """Check whether the incoming entity type matches the configured connector scope."""
        configured_scope = getattr(
            getattr(self.config, "connector", None), "scope", None
        )
        if not configured_scope:
            return True

        normalized_scope = {
            s.strip().lower().replace("_", "-")
            for s in configured_scope
            if isinstance(s, str)
        }
        # Allow x-opencti-* variants for case/task/feedback scopes
        expanded_scope = set(normalized_scope)
        for s in normalized_scope:
            expanded_scope.add(f"x-opencti-{s}")

        candidates = {
            (stix_entity.get("type") or "").lower().replace("_", "-"),
            (enrichment_entity.get("entity_type") or "").lower().replace("_", "-"),
        }
        candidates.discard("")
        if not candidates:
            return True
        return bool(candidates & expanded_scope)

    @staticmethod
    def _is_container(
        stix_entity: dict[str, Any], enrichment_entity: dict[str, Any]
    ) -> bool:
        """Determine whether the enriched entity is a STIX/OpenCTI Container."""
        parent_types = enrichment_entity.get("parent_types") or []
        if "Container" in parent_types:
            return True
        entity_type = (stix_entity.get("type") or "").lower()
        if entity_type in CONTAINER_STIX_TYPES:
            return True
        octi_type = (enrichment_entity.get("entity_type") or "").lower()
        return octi_type in CONTAINER_STIX_TYPES

    @staticmethod
    def _format_exception(err: BaseException) -> str:
        """Unwrap BaseExceptionGroup so underlying API errors are logged clearly."""
        if isinstance(err, BaseExceptionGroup):
            return "; ".join(
                CVEConnector._format_exception(sub) for sub in err.exceptions
            )
        return str(err)

    async def _async_enrich_cves(
        self, cve_ids: list[str]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Run the async NVD fetch and STIX conversion for extracted CVE IDs."""
        self.converter._rate_limiter.invalidate_lock()
        try:
            return await self.converter.enrich_cve_ids(cve_ids)
        finally:
            await self.converter.close()

    @staticmethod
    def _append_container_object_refs(
        stix_entity: dict[str, Any],
        stix_objects: list[dict[str, Any]],
        new_ref_ids: list[str],
    ) -> None:
        """Append new object IDs to the container's `object_refs` without duplicates."""
        existing_refs = list(stix_entity.get("object_refs") or [])
        existing_set = set(existing_refs)
        for ref_id in new_ref_ids:
            if ref_id and ref_id not in existing_set:
                existing_refs.append(ref_id)
                existing_set.add(ref_id)
        stix_entity["object_refs"] = existing_refs

        # Ensure the matching entity inside stix_objects also has updated object_refs
        entity_id = stix_entity.get("id")
        for obj in stix_objects:
            if isinstance(obj, dict) and obj.get("id") == entity_id:
                obj["object_refs"] = existing_refs

    @staticmethod
    def _propagate_markings(
        source_entity: dict[str, Any],
        enriched_objects: list[dict[str, Any]],
    ) -> None:
        """Preserve `object_marking_refs` from the triggering entity on generated objects."""
        marking_refs = list(source_entity.get("object_marking_refs") or [])
        if not marking_refs:
            return

        for obj in enriched_objects:
            if not isinstance(obj, dict):
                continue
            existing = list(obj.get("object_marking_refs") or [])
            merged = list(dict.fromkeys(existing + marking_refs))
            obj["object_marking_refs"] = merged

    def _build_entity_relationships(
        self,
        source_entity: dict[str, Any],
        enrichment_entity: dict[str, Any],
        vulnerability_ids: list[str],
        author_id: str,
    ) -> list[dict[str, Any]]:
        """Create STIX Relationship dicts linking extracted Vulnerabilities to the entity."""
        entity_id = source_entity.get("id")
        if not entity_id:
            return []

        entity_type = (
            source_entity.get("type") or enrichment_entity.get("entity_type") or ""
        ).lower()

        # Skip self-relationships when enriching a Vulnerability directly
        if entity_type == "vulnerability":
            return []

        relationships: list[dict[str, Any]] = []
        marking_refs = source_entity.get("object_marking_refs") or []

        for vuln_id in vulnerability_ids:
            if vuln_id == entity_id:
                continue
            rel_type = "related-to"
            rel_id = StixCoreRelationship.generate_id(rel_type, vuln_id, entity_id)
            rel_obj: dict[str, Any] = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "relationship_type": rel_type,
                "source_ref": vuln_id,
                "target_ref": entity_id,
                "created_by_ref": author_id,
            }
            if marking_refs:
                rel_obj["object_marking_refs"] = marking_refs
            relationships.append(rel_obj)

        return relationships

    def _send_bundle(self, stix_objects: list[dict[str, Any]]) -> list[Any]:
        """Serialize and send a STIX2 bundle to OpenCTI."""
        if not stix_objects:
            return []
        bundle = self.helper.stix2_create_bundle(stix_objects)
        return self.helper.send_stix2_bundle(
            bundle=bundle,
            update=True,
            cleanup_inconsistent_bundle=True,
        )

    def _passthrough_if_playbook(
        self, data: dict[str, Any], stix_objects: list[dict[str, Any]]
    ) -> None:
        """Forward the unchanged bundle only when invoked from a Playbook (no `event_type`)."""
        if not data.get("event_type") and stix_objects:
            self._send_bundle(stix_objects)

    def process_message(self, data: dict[str, Any]) -> str:
        """Process an enrichment message from OpenCTI."""
        stix_objects: list[dict[str, Any]] = list(data.get("stix_objects") or [])
        stix_entity: dict[str, Any] | None = data.get("stix_entity")
        enrichment_entity: dict[str, Any] = data.get("enrichment_entity") or {}
        entity_id = data.get("entity_id") or (
            stix_entity.get("id") if stix_entity else None
        )

        if not stix_entity:
            self.helper.connector_logger.warning(
                "[CONNECTOR] No stix_entity in enrichment payload, skipping."
            )
            return "Skipped (no stix_entity)"

        try:
            # 1. Validate entity scope
            if not self._is_in_scope(stix_entity, enrichment_entity):
                msg = "[CONNECTOR] Entity type is outside configured connector scope, skipping."
                self.helper.connector_logger.info(msg, {"entity_id": entity_id})
                self._passthrough_if_playbook(data, stix_objects)
                return msg

            # 2. Check all TLP markings on the entity against max_tlp
            tlp_allowed, effective_tlp = self._check_entity_tlp(
                enrichment_entity, stix_entity, stix_objects
            )
            if not tlp_allowed:
                msg = (
                    f"[CONNECTOR] Entity TLP ({effective_tlp}) exceeds max TLP "
                    f"({self.max_tlp}), skipping enrichment."
                )
                self.helper.connector_logger.info(
                    msg, {"entity_id": entity_id, "tlp": effective_tlp}
                )
                self._passthrough_if_playbook(data, stix_objects)
                return msg

            # 3. Extract CVE IDs from name, description, content, etc., and cap count
            cve_ids = extract_cves_from_entity(stix_entity, enrichment_entity)
            if not cve_ids:
                msg = "[CONNECTOR] No CVE identifiers found in entity."
                self.helper.connector_logger.info(msg, {"entity_id": entity_id})
                self._passthrough_if_playbook(data, stix_objects)
                return msg

            max_cves = getattr(self.config.cve, "max_cves_per_entity", 100)
            if isinstance(max_cves, int) and max_cves > 0 and len(cve_ids) > max_cves:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Truncating {len(cve_ids)} extracted CVEs to max_cves_per_entity={max_cves}",
                    {"entity_id": entity_id},
                )
                cve_ids = cve_ids[:max_cves]

            self.helper.connector_logger.info(
                f"[CONNECTOR] Extracted {len(cve_ids)} CVE(s): {', '.join(cve_ids)}",
                {"entity_id": entity_id, "cve_ids": cve_ids},
            )

            # 4. Fetch NVD data and convert to STIX objects
            enriched_objects, vulnerability_ids = asyncio.run(
                self._async_enrich_cves(cve_ids)
            )

            if not enriched_objects:
                msg = (
                    f"[CONNECTOR] No NVD data or vulnerabilities produced for "
                    f"{', '.join(cve_ids)}"
                )
                self.helper.connector_logger.info(msg, {"entity_id": entity_id})
                self._passthrough_if_playbook(data, stix_objects)
                return msg

            # Preserve markings from triggering entity on enriched objects
            self._propagate_markings(stix_entity, enriched_objects)

            author_dict = json.loads(self.converter.author.serialize())
            is_container = self._is_container(stix_entity, enrichment_entity)

            # 5. Link vulnerabilities (and any software/relationships) to the triggering entity
            relationship_objects: list[dict[str, Any]] = []
            if self.config.cve.create_relationships:
                relationship_objects = self._build_entity_relationships(
                    source_entity=stix_entity,
                    enrichment_entity=enrichment_entity,
                    vulnerability_ids=vulnerability_ids,
                    author_id=author_dict["id"],
                )

            if is_container:
                ref_ids = [
                    obj["id"]
                    for obj in (enriched_objects + relationship_objects)
                    if "id" in obj
                ]
                self._append_container_object_refs(stix_entity, stix_objects, ref_ids)

            # 6. Deduplicate and merge all objects into a single bundle.
            # If an enriched object has the same STIX ID as an incoming object in
            # stix_objects (e.g. direct Vulnerability enrichment), merge the NVD
            # fields onto a copy of the incoming object so existing custom
            # properties, labels, and markings are preserved.
            existing_by_id: dict[str, dict[str, Any]] = {
                obj["id"]: obj
                for obj in stix_objects
                if isinstance(obj, dict) and "id" in obj
            }
            merged_objects: list[dict[str, Any]] = []
            seen_ids: set[str] = set()

            for obj in (
                [author_dict] + enriched_objects + relationship_objects + stix_objects
            ):
                if not isinstance(obj, dict):
                    continue
                obj_id = obj.get("id")
                if obj_id:
                    if obj_id in seen_ids:
                        continue
                    seen_ids.add(obj_id)
                    if obj_id in existing_by_id and obj is not existing_by_id[obj_id]:
                        base = dict(existing_by_id[obj_id])
                        merged_markings = list(
                            dict.fromkeys(
                                list(base.get("object_marking_refs") or [])
                                + list(obj.get("object_marking_refs") or [])
                            )
                        )
                        base.update(obj)
                        if merged_markings:
                            base["object_marking_refs"] = merged_markings
                        obj = base
                merged_objects.append(obj)

            bundles_sent = self._send_bundle(merged_objects)
            msg = (
                f"[CONNECTOR] Enriched {len(vulnerability_ids)} CVE(s) "
                f"({', '.join(cve_ids)}), sent {len(bundles_sent)} bundle(s)."
            )
            self.helper.connector_logger.info(
                msg,
                {
                    "entity_id": entity_id,
                    "cve_ids": cve_ids,
                    "bundles_sent": len(bundles_sent),
                },
            )
            return msg

        except Exception as err:
            detail = self._format_exception(err)
            error_msg = f"[CONNECTOR] Error while enriching entity: {detail}"
            self.helper.connector_logger.error(
                error_msg, {"entity_id": entity_id, "error": detail}
            )
            # Ensure playbook continuity by forwarding the original bundle only for playbooks
            self._passthrough_if_playbook(data, stix_objects)
            return error_msg

    def run(self) -> None:
        """Start listening for enrichment messages from OpenCTI."""
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting NIST NVD CVE Internal Enrichment connector..."
        )
        self.helper.listen(message_callback=self.process_message)
