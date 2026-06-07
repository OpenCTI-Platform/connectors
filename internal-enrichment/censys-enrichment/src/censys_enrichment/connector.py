from typing import Any, Iterator

from censys_enrichment.client import Client
from censys_enrichment.converters import get_converter
from censys_enrichment.converters.base import CensysConverter
from censys_enrichment.errors import (
    EntityNotInScopeError,
    MaxTlpError,
)
from censys_enrichment.settings import ConfigLoader
from connectors_sdk.models import BaseObject
from pycti import OpenCTIConnectorHelper


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
        bundles_sent = self.helper.send_stix2_bundle(bundle=bundle)
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

    def _is_entity_tlp_allowed(self, markings: list[dict[str, Any]]) -> bool:
        """Return True if the entity's TLP is <= configured max TLP."""
        return self.helper.check_max_tlp(
            tlp=self._extract_tlp(markings=markings),
            max_tlp=self.config.censys_enrichment.max_tlp,
        )

    def _generate_octi_objects(
        self, stix_entity: dict[str, Any]
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
        return iter(converter.to_stix(observable=stix_entity))

    def _get_converter(self, entity_type: str) -> CensysConverter:
        converter = get_converter(entity_type=entity_type)
        converter.client = self.client
        return converter

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
        if not self._is_entity_tlp_allowed(markings=observable["objectMarking"]):
            raise MaxTlpError(
                f"TLP {observable['objectMarking']} of observable exceeds MAX TLP"
            )
        return original_stix_objects + [
            octi_object.to_stix2_object()
            for octi_object in self._generate_octi_objects(stix_entity=stix_entity)
        ]

    def _message_callback(self, data: dict[str, Any]) -> str:
        try:
            stix_objects = self._process(
                observable=data["enrichment_entity"],
                stix_entity=data["stix_entity"],
                original_stix_objects=data["stix_objects"],
            )
            return self._send_bundle(stix_objects=stix_objects)
        except Exception as e:
            self.helper.connector_logger.error(e)
            is_in_playbook_context = not bool(data.get("event_type"))
            if is_in_playbook_context:
                # If it's in a playbook context, we send the original bundle unchanged
                return self._send_bundle(stix_objects=data["stix_objects"])
            raise e

    def run(self) -> None:
        self.helper.listen(message_callback=self._message_callback)
