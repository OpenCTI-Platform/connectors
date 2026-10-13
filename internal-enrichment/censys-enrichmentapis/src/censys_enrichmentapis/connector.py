from typing import Any, Iterator

from censys_enrichmentapis.client import Client
from censys_enrichmentapis.converters import get_converter
from censys_enrichmentapis.converters.base import CensysConverter
from censys_enrichmentapis.errors import (
    EntityNotInScopeError,
    MarkingResolutionError,
    MaxTlpError,
)
from censys_enrichmentapis.settings import ConfigLoader
from connectors_sdk.models import BaseObject
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import OpenCTIConnectorHelper

# ``created`` timestamp OpenCTI (pycti ``prepare_export``) stamps on every
# exported TLP marking definition. Reused so a marking definition rebuilt
# here is byte-for-byte the one the platform itself would have exported.
_TLP_MARKING_CREATED = "2017-01-20T00:00:00.000Z"


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
        entity_tlp = self._extract_tlp(markings=markings)
        max_tlp = self.config.censys_enrichmentapis.max_tlp
        if not self.helper.check_max_tlp(tlp=entity_tlp, max_tlp=max_tlp):
            raise MaxTlpError(
                f"TLP {entity_tlp} of observable exceeds MAX TLP {max_tlp}"
            )

    @staticmethod
    def _marking_id(marking: dict[str, Any]) -> str | None:
        """Return the STIX id of an OpenCTI ``objectMarking`` entry."""
        marking_id = marking.get("standard_id")
        if isinstance(marking_id, str):
            return marking_id
        definition_type = marking.get("definition_type")
        definition = marking.get("definition")
        if isinstance(definition_type, str) and isinstance(definition, str):
            return PyctiMarkingDefinition.generate_id(definition_type, definition)
        return None

    @classmethod
    def _extract_marking_refs(
        cls, stix_entity: dict[str, Any], markings: list[dict[str, Any]]
    ) -> list[str]:
        """Return the marking refs of the enriched entity, source of truth first.

        ``stix_entity["object_marking_refs"]`` is what OpenCTI exported for the
        entity and is preferred; the OpenCTI ``objectMarking`` list is only used
        as a fallback when the STIX entity carries no refs.
        """
        entity_refs = stix_entity.get("object_marking_refs")
        if entity_refs:
            return list(dict.fromkeys(entity_refs))

        marking_refs = [
            marking_id
            for marking in markings
            if (marking_id := cls._marking_id(marking)) is not None
        ]
        return list(dict.fromkeys(marking_refs))

    @classmethod
    def _materialize_marking_definition(
        cls, marking: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Rebuild a STIX marking definition from an OpenCTI ``objectMarking``.

        Mirrors the shape produced by pycti's ``prepare_export`` (the very
        objects OpenCTI puts in ``data["stix_objects"]``), so any marking type
        the platform knows (TLP, PAP, statement, custom) round-trips without
        special-casing and is accepted by the worker as-is.
        """
        definition_type = marking.get("definition_type")
        definition = marking.get("definition")
        marking_id = cls._marking_id(marking)
        if (
            not isinstance(definition_type, str)
            or not isinstance(definition, str)
            or marking_id is None
        ):
            return None

        if definition_type.upper() == "TLP":
            created = _TLP_MARKING_CREATED
        else:
            created = marking.get("created") or _TLP_MARKING_CREATED
        return {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": marking_id,
            "created": created,
            "definition_type": definition_type.lower(),
            "name": definition,
            "definition": {
                definition_type.lower(): definition.lower().replace("tlp:", "")
            },
        }

    @classmethod
    def _resolve_source_markings(
        cls,
        stix_entity: dict[str, Any],
        markings: list[dict[str, Any]],
        original_stix_objects: list[dict[str, Any]],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        """Return the marking refs to apply to derived objects and the
        marking-definition objects that must be added to the bundle for them.

        Every source marking ref is preserved: a ref already bundled is used
        as-is, a ref only known from ``objectMarking`` is materialized, and a
        ref that cannot be resolved raises ``MarkingResolutionError`` rather
        than silently letting ``cleanup_inconsistent_bundle`` strip it (which
        would publish the derived data with downgraded, or no, markings).
        An empty result means the source is genuinely unmarked, in which case
        the builder applies the connector's default TLP:CLEAR marking.
        """
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
        missing_definitions = []
        for marking_ref in requested_refs:
            if marking_ref in bundled_definition_ids:
                continue
            definition = materialized_definitions.get(marking_ref)
            if definition is None:
                raise MarkingResolutionError(
                    f"Marking {marking_ref} of the enriched entity cannot be "
                    "resolved from the bundle or the entity markings; refusing "
                    "to enrich with downgraded markings"
                )
            missing_definitions.append(definition)
        return requested_refs, missing_definitions

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
        except Exception as error:
            # pycti's ``AppLogger.error`` already attaches ``exc_info``, so the
            # traceback is logged; a bare ``raise`` below preserves it as well.
            self.helper.connector_logger.error(
                "Error processing message", {"error": str(error)}
            )
            is_in_playbook_context = not bool(data.get("event_type"))
            if is_in_playbook_context:
                # If it's in a playbook context, we send the original bundle unchanged
                return self._send_bundle(stix_objects=data["stix_objects"])
            raise

    def run(self) -> None:
        self.helper.listen(message_callback=self._message_callback)
