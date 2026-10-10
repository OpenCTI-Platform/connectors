"""XposedOrNot internal-enrichment connector.

Enriches Email-Addr observables with their data-breach exposure. The email
address is sent over TLS to xposedornot.com; XPOSEDORNOT_MAX_TLP gates what
may leave the platform.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from connectors_sdk.models import Reference, TLPMarking
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import OpenCTIConnectorHelper
from src.xposedornot.client_api import XposedOrNotClient, redact, usable_score
from src.xposedornot.converter_to_stix import ConverterToStix
from src.xposedornot.errors import (
    EnrichmentError,
    EnrichmentSkipped,
    EntityNotInScopeError,
    InvalidEmailError,
    MaxTlpError,
)
from src.xposedornot.settings import ConnectorSettings

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
OWN_SOURCE_NAME = "XposedOrNot"
OWN_REFERENCE = {
    "source_name": OWN_SOURCE_NAME,
    "url": "https://xposedornot.com",
    "description": "XposedOrNot breach exposure check",
}
OWNED_LABELS = frozenset({"data-breach", "plaintext-password-exposure"})
TLP_LEVELS = (
    "TLP:CLEAR",
    "TLP:WHITE",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
)
TLP_IDS = {
    PyctiMarkingDefinition.generate_id("TLP", level): level for level in TLP_LEVELS
}


class XposedOrNotConnector:
    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        client: XposedOrNotClient | None = None,
    ) -> None:
        self.config = config
        self.helper = helper
        settings = config.xposedornot
        self.client = client or XposedOrNotClient(
            helper,
            settings.api_key.get_secret_value() if settings.api_key else None,
            str(settings.api_base_url),
        )
        self.converter = ConverterToStix(
            author=ConverterToStix.make_author(),
            max_table_rows=settings.max_note_breaches,
        )

    def _send_bundle(
        self, stix_objects: list[dict[str, Any]], update: bool = False
    ) -> None:
        bundle = self.helper.stix2_create_bundle(list(stix_objects))
        self.helper.send_stix2_bundle(
            bundle, update=update, cleanup_inconsistent_bundle=True
        )

    @staticmethod
    def _source_tlps(
        markings: list[dict[str, Any]],
        stix_entity: dict[str, Any],
        stix_objects: list[dict[str, Any]],
    ) -> list[Any]:
        """Every TLP value the source carries: resolved markings, well-known
        reference ids and TLP definitions bundled alongside the entity. A
        reference that resolves to nothing is refused."""
        bundled = {
            obj.get("id"): obj
            for obj in stix_objects
            if isinstance(obj, dict) and obj.get("type") == "marking-definition"
        }
        resolved = set(bundled) | set(TLP_IDS)
        values = []
        for marking in markings:
            if marking.get("definition_type") == "TLP":
                values.append(marking.get("definition"))
            ref = marking.get("standard_id")
            if not ref and marking.get("definition_type") and marking.get("definition"):
                ref = PyctiMarkingDefinition.generate_id(
                    marking["definition_type"], marking["definition"]
                )
            resolved.add(ref)
        for ref in stix_entity.get("object_marking_refs") or []:
            definition = bundled.get(ref) or {}
            kind = definition.get("x_opencti_definition_type") or definition.get(
                "definition_type"
            )
            if ref in TLP_IDS:
                values.append(TLP_IDS[ref])
            elif str(kind or "").upper() == "TLP":
                values.append(
                    definition.get("x_opencti_definition") or definition.get("name")
                )
            elif ref not in resolved:
                raise MaxTlpError(
                    f"Marking reference {ref!r} of the observable cannot be"
                    " resolved; skipping"
                )
        return values

    def _validate_tlp(self, values: list[Any]) -> None:
        max_tlp = self.config.xposedornot.max_tlp
        for tlp in values:
            if not isinstance(tlp, str) or not self.helper.check_max_tlp(tlp, max_tlp):
                raise MaxTlpError(
                    f"TLP marking {tlp!r} of the observable is unreadable or above"
                    f" the maximum allowed ({max_tlp}); skipping"
                )

    @staticmethod
    def _marking_refs(
        stix_entity: dict[str, Any], markings: list[dict[str, Any]]
    ) -> list[str]:
        refs = list(stix_entity.get("object_marking_refs") or [])
        for marking in markings:
            ref = marking.get("standard_id")
            if not ref and marking.get("definition_type") and marking.get("definition"):
                ref = PyctiMarkingDefinition.generate_id(
                    marking["definition_type"], marking["definition"]
                )
            if ref:
                refs.append(ref)
        return list(dict.fromkeys(refs))

    def _enriched_observable(
        self, stix_entity: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        """A copy of the observable carrying the score, labels and reference."""
        entity = deepcopy(stix_entity)
        score = usable_score(result.get("risk_score"))
        if self.config.xposedornot.update_score and score is not None:
            entity["x_opencti_score"] = score

        existing = (entity.get("x_opencti_labels") or []) + (
            entity.pop("labels", None) or []
        )
        labels = [
            label
            for label in dict.fromkeys(existing)
            if isinstance(label, str) and label.casefold() not in OWNED_LABELS
        ]
        labels.append("data-breach")
        if self.converter.has_plaintext_exposure(result["breaches"]):
            labels.append("plaintext-password-exposure")
        entity["x_opencti_labels"] = labels

        references = (entity.pop("external_references", None) or []) + (
            entity.get("x_opencti_external_references") or []
        )
        kept: list[dict[str, Any]] = []
        seen: set[str] = set()
        for ref in references:
            if not isinstance(ref, dict) or ref.get("source_name") == OWN_SOURCE_NAME:
                continue
            key = json.dumps(ref, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                kept.append(ref)
        entity["x_opencti_external_references"] = kept + [dict(OWN_REFERENCE)]
        return entity

    def _forward(self, data: dict[str, Any], message: str) -> str:
        """Inside a playbook, hand the bundle back untouched; return the status."""
        if not data.get("event_type"):
            self._send_bundle(data["stix_objects"])
        return message

    def _redact(self, text: str, data: dict[str, Any]) -> str:
        observable = data.get("enrichment_entity") or {}
        entity = data.get("stix_entity") or {}
        values = [observable.get("observable_value"), entity.get("value")]
        secrets = [str(value).strip() for value in values if value]
        return redact(text, *secrets, self.client.api_key)

    def _process(self, data: dict[str, Any]) -> str:
        observable = data["enrichment_entity"]
        stix_entity = data["stix_entity"]
        entity_type = observable.get("entity_type")
        stix_type = str(stix_entity.get("id") or "").split("--")[0]
        if entity_type not in self.config.connector.scope or stix_type != "email-addr":
            raise EntityNotInScopeError(
                f"Unsupported entity type: {entity_type or stix_type}"
            )
        markings = observable.get("objectMarking") or []
        self._validate_tlp(
            self._source_tlps(markings, stix_entity, data["stix_objects"])
        )
        email = str(
            observable.get("observable_value") or stix_entity.get("value") or ""
        )
        email = email.strip().lower()
        if not EMAIL_RE.match(email):
            raise InvalidEmailError("The observable value is not a valid email address")

        result = self.client.lookup(email)
        if not result:
            return self._forward(
                data, "No known breach exposure for this email address (XposedOrNot)"
            )

        tlp = TLPMarking(level=self.config.xposedornot.tlp_level)
        note_markings = [tlp] + [
            Reference(id=ref)
            for ref in self._marking_refs(stix_entity, markings)
            if ref != tlp.id
        ]
        note = self.converter.build_note(
            stix_entity["id"],
            result,
            markings=note_markings,
            observed_at=observable.get("created_at"),
        )
        enriched = self._enriched_observable(stix_entity, result)
        objects = [
            enriched if obj.get("id") == enriched["id"] else obj
            for obj in data["stix_objects"]
        ]
        if enriched not in objects:
            objects.append(enriched)
        objects += [
            self.converter.author.to_stix2_object(),
            tlp.to_stix2_object(),
            note.to_stix2_object(),
        ]
        self._send_bundle(objects, update=True)

        first, latest = self.converter.years(result["breaches"])
        span = f" (first {first}, latest {latest})" if first and latest else ""
        return (
            f"Found {len(result['breaches'])} breach(es){span};"
            " observable updated and summary note attached"
        )

    def _message_callback(self, data: dict[str, Any]) -> str:
        try:
            return self._process(data)
        except EnrichmentSkipped as skipped:
            message = self._redact(str(skipped), data)
            self.helper.connector_logger.info(message)
            return self._forward(data, message)
        except Exception as error:
            failure = f"{type(error).__name__}: {self._redact(str(error), data)}"
        self.helper.connector_logger.error(
            "Error processing message", meta={"error": failure}
        )
        if not data.get("event_type"):
            return self._forward(data, "Internal error (see logs)")
        raise EnrichmentError(failure)

    def run(self) -> None:
        self.helper.listen(message_callback=self._message_callback)
