from typing import Any


from censys_enrichment.client import Client
from censys_enrichment.config import Config
from pycti import OpenCTIConnectorHelper


class EntityNotInScopeError(Exception):
    """Custom exception for entity not in scope"""


class MaxTlpError(Exception):
    """Custom exception for exceeding maximum TLP level"""


class EntityTypeNotSupportedError(Exception):
    """Custom exception for unsupported entity type"""


class Connector:
    """Shodan InternetDB connector"""

    def __init__(
        self,
        config: Config,
        helper: OpenCTIConnectorHelper,
        client: Client,
    ) -> None:
        self.config = config
        self.helper = helper
        self.client = client

    def _send_bundle(self, stix_objects: list[dict[str, Any]]) -> str:
        bundle = self.helper.stix2_create_bundle(items=stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(bundle=bundle)
        return f"Sending {str(len(bundles_sent))} stix bundle(s) for worker import"

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

    def _get_related_stix_objects(
        self, observable: dict[str, Any]
    ) -> list[dict[str, Any]]:
        match observable["entity_type"]:
            case "IPv4-Addr" | "IPv6-Addr":
                host = self.client.fetch_ip(observable["value"])

            case _:
                raise EntityTypeNotSupportedError(
                    f"Observable type {observable['entity_type']} not supported"
                )

    def _process(
        self, original_stix_objects: list[dict[str, Any]], observable: dict[str, Any]
    ) -> list[dict[str, Any]]:
        if not self._is_entity_in_scope(entity_type=observable["entity_type"]):
            raise EntityNotInScopeError(
                f"Unsupported entity type: {observable['entity_type']}"
            )
        if not self._is_entity_tlp_allowed(markings=observable["objectMarking"]):
            raise MaxTlpError(
                f"TLP {observable['objectMarking']} of observable exceeds MAX TLP"
            )
        return original_stix_objects + self._get_related_stix_objects(
            observable=observable
        )

    def _message_callback(self, data: dict[str, Any]) -> str:
        try:
            stix_objects = self._process(
                original_stix_objects=data["stix_objects"],
                observable=data["enrichment_entity"],
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
