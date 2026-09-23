import json
from typing import Any, Iterator

from censys_enrichmentapis.client import Client
from censys_enrichmentapis.converters import get_converter
from censys_enrichmentapis.converters.base import CensysConverter
from censys_enrichmentapis.errors import (
    EntityNotInScopeError,
    MaxTlpError,
)
from censys_enrichmentapis.settings import ConfigLoader
from connectors_sdk.models import BaseObject, TLPMarking
from connectors_sdk.models.enums import TLPLevel
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import OpenCTIConnectorHelper
from stix2.v21 import MarkingDefinition as Stix2MarkingDefinition


class Connector:
    """Censys connector"""

    def __init__(
        self,
        config: ConfigLoader,
        helper: OpenCTIConnectorHelper,
        client: Client,
    ) -> None:
        self.config = config
        self.helper = helper
        self.client = client

    def _send_bundle(self, stix_objects: list[dict[str, Any]]) -> str:
        bundle = self.helper.stix2_create_bundle(items=stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=bundle, cleanup_inconsistent_bundle=True
        )
        return f"Sending {len(bundles_sent)} stix bundle(s) for worker import"

    def _is_entity_in_scope(self, entity_type: str) -> bool:
        """Return True if the entity type is supported by the connector scope."""
        return entity_type in self.config.connector.scope

    def _extract_tlp(self, markings: list[dict[str, Any]]) -> str | None:
        """Return the first TLP string (e.g., 'TLP:AMBER'), or None if not present."""
        return next(
            (
                marking["definition"]
                for marking in markings
                if marking["definition_type"] == "TLP"
            ),
            None,
        )

    def _validate_entity_tlp(self, markings: list[dict[str, Any]]) -> None:
        """Reject an entity whose TLP exceeds the configured maximum."""
        if not self.helper.check_max_tlp(
            tlp=self._extract_tlp(markings=markings),
            max_tlp=self.config.censys_enrichmentapis.max_tlp,
        ):
            raise MaxTlpError(f"TLP {markings} of observable exceeds MAX TLP")

    @staticmethod
    def _extract_marking_refs(
        stix_entity: dict[str, Any], markings: list[dict[str, Any]]
    ) -> list[str]:
        entity_refs = stix_entity.get("object_marking_refs")
        if entity_refs:
            return list(dict.fromkeys(entity_refs))

        marking_refs = []
        for marking in markings:
            marking_ref = marking.get("standard_id")
            if not isinstance(marking_ref, str):
                marking_ref = PyctiMarkingDefinition.generate_id(
                    marking["definition_type"], marking["definition"]
                )
            marking_refs.append(marking_ref)
        return list(dict.fromkeys(marking_refs))

    @staticmethod
    def _materialize_marking_definition(
        marking: dict[str, Any],
    ) -> dict[str, Any] | None:
        definition_type = marking.get("definition_type")
        definition = marking.get("definition")
        if not isinstance(definition_type, str) or not isinstance(definition, str):
            return None

        definition_type = definition_type.upper()
        definition = definition.upper()
        canonical_id = PyctiMarkingDefinition.generate_id(definition_type, definition)
        marking_id = marking.get("standard_id")
        if not isinstance(marking_id, str):
            marking_id = canonical_id
        if marking_id != canonical_id:
            return None

        if definition_type == "TLP":
            try:
                level = TLPLevel(definition.removeprefix("TLP:").lower())
            except ValueError:
                return None
            stix_marking = TLPMarking(level=level).to_stix2_object()
        elif definition_type == "PAP" and definition in {
            "PAP:CLEAR",
            "PAP:GREEN",
            "PAP:AMBER",
            "PAP:RED",
        }:
            stix_marking = Stix2MarkingDefinition(
                id=canonical_id,
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="PAP",
                x_opencti_definition=definition,
            )
        else:
            return None

        return json.loads(stix_marking.serialize())

    @classmethod
    def _resolve_source_markings(
        cls,
        stix_entity: dict[str, Any],
        markings: list[dict[str, Any]],
        original_stix_objects: list[dict[str, Any]],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        requested_refs = cls._extract_marking_refs(stix_entity, markings)
        bundled_definition_ids = {
            stix_object.get("id")
            for stix_object in original_stix_objects
            if stix_object.get("type") == "marking-definition"
        }
        materialized_definitions = {
            definition["id"]: definition
            for marking in markings
            if (definition := cls._materialize_marking_definition(marking)) is not None
        }
        available_definition_ids = bundled_definition_ids | set(
            materialized_definitions
        )
        resolved_refs = [
            marking_ref
            for marking_ref in requested_refs
            if marking_ref in available_definition_ids
        ]
        missing_definitions = [
            materialized_definitions[marking_ref]
            for marking_ref in resolved_refs
            if marking_ref not in bundled_definition_ids
        ]
        return resolved_refs, missing_definitions

    def _generate_octi_objects(
        self,
        stix_entity: dict[str, Any],
        primary_observable_labels: list[str] | None = None,
        marking_refs: list[str] | None = None,
    ) -> Iterator[BaseObject]:
        # Annotate ``Iterator`` (not ``Generator``) so the type
        # matches the ``list_iterator`` returned by
        # ``iter(converter.to_stix(...))``. Keeping ``return
        # iter(...)`` instead of rewriting as a real ``yield from``
        # generator is deliberate: the converter dispatch
        # (``_get_converter`` → ``get_converter`` →
        # ``EntityTypeNotSupportedError``) must run eagerly so
        # misconfigured entity types surface at call time rather
        # than only when something starts iterating the returned
        # object — the test suite (and the ``_message_callback``
        # error path that wraps this) both rely on the eager
        # behaviour.
        converter = self._get_converter(entity_type=stix_entity["type"])
        stix_objects = converter.to_stix(
            observable=stix_entity,
            marking_refs=marking_refs,
        )
        if primary_observable_labels is not None:
            primary_observable_labels.extend(converter.primary_observable_labels)
        return iter(stix_objects)

    def _get_converter(self, entity_type: str) -> CensysConverter:
        converter = get_converter(entity_type=entity_type)
        converter.client = self.client
        return converter

    @staticmethod
    def _merge_primary_observable_labels(
        stix_objects: list[dict[str, Any]],
        stix_id: str,
        labels: list[str],
    ) -> None:
        if not labels:
            return

        for stix_object in stix_objects:
            if stix_object.get("id") != stix_id:
                continue
            existing_labels = stix_object.get("x_opencti_labels", [])
            stix_object["x_opencti_labels"] = list(
                dict.fromkeys([*existing_labels, *labels])
            )
            return

    def _process(
        self,
        observable: dict[str, Any],
        stix_entity: dict[str, Any],
        original_stix_objects: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not self._is_entity_in_scope(entity_type=observable["entity_type"]):
            raise EntityNotInScopeError(
                f"Unsupported entity type: {observable['entity_type']}"
            )
        self._validate_entity_tlp(markings=observable["objectMarking"])
        marking_refs, marking_definitions = self._resolve_source_markings(
            stix_entity=stix_entity,
            markings=observable["objectMarking"],
            original_stix_objects=original_stix_objects,
        )
        primary_observable_labels: list[str] = []
        generated_stix_objects = [
            octi_object.to_stix2_object()
            for octi_object in self._generate_octi_objects(
                stix_entity=stix_entity,
                primary_observable_labels=primary_observable_labels,
                marking_refs=marking_refs,
            )
        ]
        self._merge_primary_observable_labels(
            stix_objects=original_stix_objects,
            stix_id=stix_entity["id"],
            labels=primary_observable_labels,
        )
        return original_stix_objects + marking_definitions + generated_stix_objects

    def _message_callback(self, data: dict[str, Any]) -> str:
        try:
            stix_objects = self._process(
                observable=data["enrichment_entity"],
                stix_entity=data["stix_entity"],
                original_stix_objects=data["stix_objects"],
            )
            return self._send_bundle(stix_objects=stix_objects)
        except Exception:
            self.helper.connector_logger.exception("Error processing message")
            is_in_playbook_context = not bool(data.get("event_type"))
            if is_in_playbook_context:
                # If it's in a playbook context, we send the original bundle unchanged
                return self._send_bundle(stix_objects=data["stix_objects"])
            raise

    def run(self) -> None:
        self.helper.listen(message_callback=self._message_callback)
