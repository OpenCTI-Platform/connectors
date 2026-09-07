from datetime import datetime, timezone
from typing import Any

import pycti
from connector.settings import ConnectorSettings
from connector.triage import TriageResult, triage_entity
from pycti import OpenCTIConnectorHelper


class DualSignalTriageConnector:
    """Internal enrichment that encodes Gate→Prove dual-signal triage labels.

    Hard rule: ML-only confidence must never be equated to a signature true positive
    for automated containment.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.tlp = None

    def entity_in_scope(self, data: dict) -> bool:
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["entity_id"].split("--")[0].lower()
        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        markings = opencti_entity.get("objectMarking") or []
        for marking_definition in markings:
            if marking_definition.get("definition_type") == "TLP":
                self.tlp = marking_definition.get("definition")
        valid_max_tlp = self.helper.check_max_tlp(
            self.tlp, self.config.dual_signal_triage.max_tlp_level
        )
        if not valid_max_tlp:
            raise ValueError(
                "[CONNECTOR] TLP of the entity is greater than MAX TLP; skipping enrichment"
            )

    def _ensure_labels(self, result: TriageResult) -> list[str]:
        label_ids: list[str] = []
        for value in result.labels:
            color = "#d32f2f" if result.deny_auto_contain else "#2e7d32"
            if "escalate" in value or "ml-only" in value:
                color = "#ed6c02"
            if "fix-now" in value:
                color = "#1565c0"
            label = self.helper.api.label.read_or_create_unchecked(
                value=value, color=color
            )
            if label and label.get("id"):
                label_ids.append(label["id"])
                self.helper.api.stix_domain_object.add_label(
                    id=self._current_entity_id, label_id=label["id"]
                )
        return label_ids

    def _append_labels_to_stix(self, stix_entity: dict, result: TriageResult) -> None:
        existing = stix_entity.get("labels") or []
        merged = list(dict.fromkeys([*existing, *result.labels]))
        stix_entity["labels"] = merged
        extensions = stix_entity.setdefault("extensions", {})
        octi = extensions.setdefault(
            "extension-definition--ea279b57-12d3-40be-9208-279dbcbc3d70", {}
        )
        octi["dual_signal_basis"] = result.signal_basis
        octi["dual_signal_disposition"] = result.disposition
        octi["deny_auto_contain"] = result.deny_auto_contain

    def _create_note_stix(
        self, stix_entity: dict, result: TriageResult
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        abstract = f"Dual-signal triage: {result.disposition}"
        content = (
            f"**Signal basis:** `{result.signal_basis}`\n\n"
            f"**Disposition:** `{result.disposition}`\n\n"
            f"**Deny auto-contain:** `{result.deny_auto_contain}`\n\n"
            f"{result.summary}\n\n"
            "Doctrine: machine-learning confidence is not a signature true positive."
        )
        return {
            "type": "note",
            "spec_version": "2.1",
            "id": pycti.Note.generate_id(None, content, abstract),
            "created": now,
            "modified": now,
            "abstract": abstract,
            "content": content,
            "object_refs": [stix_entity["id"]],
            "labels": list(result.labels),
        }

    def process_message(self, data: dict) -> str:
        try:
            opencti_entity = data["enrichment_entity"]
            self._current_entity_id = opencti_entity.get("id") or data.get("entity_id")
            self.extract_and_check_markings(opencti_entity)

            stix_objects = list(data.get("stix_objects") or [])
            stix_entity = data["stix_entity"]

            if not self.entity_in_scope(data):
                if not data.get("event_type"):
                    return self._send_bundle(stix_objects)
                raise ValueError(
                    f"Unsupported entity type for dual-signal triage: "
                    f"{opencti_entity.get('entity_type')}"
                )

            result = triage_entity({**opencti_entity, **stix_entity})
            self.helper.connector_logger.info(
                "[CONNECTOR] Dual-signal triage result",
                {
                    "signal_basis": result.signal_basis,
                    "disposition": result.disposition,
                    "deny_auto_contain": result.deny_auto_contain,
                },
            )

            self._ensure_labels(result)
            self._append_labels_to_stix(stix_entity, result)

            # Keep a single updated copy of the enriched entity in the bundle
            replaced = False
            for idx, obj in enumerate(stix_objects):
                if obj.get("id") == stix_entity.get("id"):
                    stix_objects[idx] = stix_entity
                    replaced = True
                    break
            if not replaced:
                stix_objects.append(stix_entity)

            if self.config.dual_signal_triage.create_note:
                stix_objects.append(self._create_note_stix(stix_entity, result))

            return self._send_bundle(stix_objects)
        except Exception as err:
            return self.helper.connector_logger.error(
                "[CONNECTOR] Unexpected Error occurred", {"error_message": str(err)}
            )

    def _send_bundle(self, stix_objects: list) -> str:
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_objects_bundle)
        return f"Sending {len(bundles_sent)} stix bundle(s) for worker import"

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
