from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Protocol

from connector.models import EventIndicator
from pydantic import ValidationError

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from cortex_xdr_client import CortexXdrClient
    from pycti import OpenCTIConnectorHelper


_SUPPORTED_EVENTS = {"create", "update", "delete"}
_SUPPORTED_ENTITY_TYPES = {"indicator"}
_SUPPORTED_OBSERVABLE_TYPES = {
    "domain-name",
    "hostname",
    "ipv4-addr",
    "ipv6-addr",
    "stixfile",
}

_OPENCTI_OBSERVABLE_TYPES_TO_XDR_IOC_TYPES = {
    "domain-name": "DOMAIN_NAME",
    "hostname": "DOMAIN_NAME",
    "ipv4-addr": "IP",
    "ipv6-addr": "IP",
    "stixfile": {"name": "FILENAME", "hash": "HASH"},
    # XDR IOC types `PATH` and `MIXED` are not mapped for now
}


class StreamMessage(Protocol):
    """Type for the SSE message passed to `listen_stream` callbacks.

    Only the attributes actually consumed by this connector are declared,
    decoupling us from `filigran_sseclient.sseclient.Event`'s concrete shape
    (and from adding it as an explicit dependency just for typing).
    """

    event: str
    data: str


class Connector:
    """
    Cortex XDR Intel stream connector.

    ---

    Attributes:
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
        settings (ConnectorSettings):
            Store the connector's configuration.
        client (CortexXdrClient):
            Provide methods to request the Cortex XDR API.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        settings: ConnectorSettings,
        client: CortexXdrClient,
    ) -> None:
        self.helper = helper
        self.settings = settings
        self.client = client

        # Reusable exit message for fatal errors logging
        self._exit_message = (
            "Connector will exit to avoid further errors and/or exhausting the stream.\n"
            "Please check connector's logs and report/fix the issue before restarting."
        )

    def _parse_indicator(self, data: dict[str, Any]) -> EventIndicator:
        """Build a minimal, internal representation of an Indicator's stream
        `data` payload. Field casting/validation is delegated to `EventIndicator`.
        """
        # Use `observable_values` extension provided by OpenCTI to extract the list of observables
        observable_values = (
            self.helper.get_attribute_in_extension("observable_values", data) or []
        )
        # Filter out observable types not supported by Cortex XDR Client
        supported_observable_values = [
            observable_value
            for observable_value in observable_values
            if observable_value.get("type", "").lower() in _SUPPORTED_OBSERVABLE_TYPES
        ]

        # Parse and validate the indicator in stream `data` payload
        return EventIndicator(
            id=self.helper.get_attribute_in_extension("id", data),
            description=data.get("description"),
            observables=supported_observable_values,
            valid_until=data.get("valid_until"),
            score=self.helper.get_attribute_in_extension("score", data),
        )

    def _process_message(self, msg: StreamMessage) -> None:
        """Process a single stream event message.

        Unsupported event or entity types are logged as a warning and
        skipped. Any failure while decoding, parsing, or validating the
        message (JSON decode error, `Indicator` validation error, or any
        other unexpected exception) is logged with context and re-raised,
        deliberately letting `pycti` kill the connector process rather than
        risk silently missing or corrupting further events.
        """
        event = msg.event
        if event not in _SUPPORTED_EVENTS:
            self.helper.connector_logger.warning(
                "Unsupported event type, skipping it",
                {"event": event},
            )
            return

        try:
            message_data = json.loads(msg.data)
        except json.JSONDecodeError as err:
            # This should never happen and if it does, it indicates a breaking change in `pycti`.
            # To avoid data loss, the connector must stop and the issue must be investigated and fixed before resuming.
            self.helper.connector_logger.error(
                f"Failed to parse stream event's `data` payload as JSON.\n{self._exit_message}",
                {
                    "event": event,
                    "data": msg.data,
                    "error": err,
                },
            )
            raise  # let `pycti` kill the connector process

        entity_data = message_data.get("data", {})
        entity_type = entity_data.get("type")
        if entity_type not in _SUPPORTED_ENTITY_TYPES:
            self.helper.connector_logger.warning(
                "Unsupported entity type, skipping it",
                {
                    "event": event,
                    "entity_type": entity_type,
                },
            )
            return

        try:
            indicator = self._parse_indicator(entity_data)

            self.helper.connector_logger.info(
                "Parsed observable(s) from stream event",
                {
                    "event": event,
                    "indicator_id": indicator.id,
                    "observables_count": len(indicator.observables),
                },
            )
        except ValidationError as err:
            # This should never happen and if it does, it indicates a breaking change in `pycti`.
            # To avoid data loss, the connector must stop and the issue must be investigated and fixed before resuming.
            self.helper.connector_logger.error(
                f"Failed to parse indicator and/or observables from stream event.\n{self._exit_message}",
                {
                    "event": event,
                    "entity_data": entity_data,
                    "error": err,
                },
            )
            raise  # let `pycti` kill the connector process

        try:
            if event in {"create", "update"}:
                pass  # TODO: upsert in Cortex XDR
            elif event == "delete":
                pass  # TODO: delete from Cortex XDR

        except Exception as err:
            # Repetitive unexpected errors could consume the stream in vain (no action performed).
            # To avoid data loss, the connector must stop and the issue must be investigated and fixed before resuming.
            self.helper.connector_logger.error(
                f"Unexpected error while processing stream event.\n{self._exit_message}",
                {
                    "event": event,
                    "entity_data": entity_data,
                    "error": err,
                },
            )
            raise  # let `pycti` kill the connector process

    def start(self) -> None:
        """Start the connector's main loop: listen to the OpenCTI stream and process each message."""
        self.helper.listen_stream(self._process_message)
