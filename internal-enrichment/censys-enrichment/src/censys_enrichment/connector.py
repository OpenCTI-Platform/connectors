from typing import Any, Generator

from censys_enrichment.client import Client
from censys_enrichment.converter import Converter
from censys_enrichment.settings import ConfigLoader
from connectors_sdk.models import BaseObject
from pycti import OpenCTIConnectorHelper


class EntityNotInScopeError(Exception):
    """Custom exception for entity not in scope"""


class MaxTlpError(Exception):
    """Custom exception for exceeding maximum TLP level"""


class EntityTypeNotSupportedError(Exception):
    """Custom exception for unsupported entity type"""


class Connector:
    """Censys connector"""

    def __init__(
        self,
        config: ConfigLoader,
        helper: OpenCTIConnectorHelper,
        client: Client,
        converter: Converter,
    ) -> None:
        self.config = config
        self.helper = helper
        self.client = client
        self.converter = converter

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
    ) -> Generator[BaseObject, None, None]:
        match stix_entity["type"]:
            case "ipv4-addr" | "ipv6-addr":
                return self.converter.generate_octi_objects(
                    stix_entity=stix_entity,
                    data=self.client.fetch_ip(stix_entity["value"]),
                )
            case "x509-certificate":
                return self.converter.generate_octi_objects_from_certs(
                    certs=list(self.client.fetch_certs(hashes=stix_entity["hashes"])),
                )
            case "domain-name":

                def _generate_domain_objects():
                    # yield objects from associated hosts
                    yield from self.converter.generate_octi_objects_from_hosts(
                        stix_entity=stix_entity,
                        hosts=list(self.client.fetch_hosts(stix_entity["value"])),
                    )
                    # yield certificates associated with the domain
                    yield from self.converter.generate_octi_objects_from_domain_certs(
                        stix_entity=stix_entity,
                        certs=list(
                            self.client.fetch_certs_by_domain(stix_entity["value"])
                        ),
                    )

                return _generate_domain_objects()

            case _:
                raise EntityTypeNotSupportedError(
                    f"Observable type {stix_entity['type']} not supported"
                )

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
