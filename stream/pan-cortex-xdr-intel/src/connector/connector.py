from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Protocol

from connector.models import CortexXdrIoc, OctiIndicator
from connectors_sdk import (
    ApiForbiddenError,
    ApiNotFoundError,
    ApiRateLimitError,
    ApiServerError,
    ApiUnauthorizedError,
)
from cortex_xdr_client import CortexXdrApiError
from pydantic import ValidationError

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from cortex_xdr_client import CortexXdrClient
    from pycti import OpenCTIConnectorHelper


_SUPPORTED_EVENTS = {"create", "update", "delete"}
_SUPPORTED_ENTITY_TYPES = {"indicator"}
_SUPPORTED_OBSERVABLE_TYPES = {
    "domain-name",
    "ipv4-addr",
    "ipv6-addr",
    "stixfile",
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

    def _build_octi_indicator(self, data: dict[str, Any]) -> OctiIndicator:
        """Build a minimal, internal representation of an Indicator's stream
        `data` payload. Field casting/validation is delegated to `OctiIndicator`.
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

        # Build and validate the indicator from stream `data` payload
        return OctiIndicator(
            id=self.helper.get_attribute_in_extension("id", data),
            description=data.get("description"),
            observables=supported_observable_values,
            valid_until=data.get("valid_until"),
            score=self.helper.get_attribute_in_extension("score", data),
        )

    def _extract_xdr_iocs(self, octi_indicator: OctiIndicator) -> list[CortexXdrIoc]:
        """Build `CortexXdrIoc` from `octi_indicator` and its observables,
        mapping OpenCTI fields to Cortex XDR's IOC fields.

        /!\\ Observables without a supported mapping are skipped silently.
        """
        if not octi_indicator.observables:
            return []

        # Map OpenCTI indicator's fields to Cortex XDR IOC fields
        # TODO: fix the mapping so it correspond to the mapping defined in the MVP
        if octi_indicator.score is None:
            xdr_severity = None
        elif octi_indicator.score >= 80:
            xdr_severity = "SEV_040_HIGH"
        elif octi_indicator.score >= 60:
            xdr_severity = "SEV_030_MEDIUM"
        elif octi_indicator.score >= 40:
            xdr_severity = "SEV_020_LOW"
        elif octi_indicator.score >= 20:
            xdr_severity = "SEV_010_INFO"
        else:
            xdr_severity = None

        xdr_expiration_timestamp = (
            int(octi_indicator.valid_until.timestamp()) * 1000
            if octi_indicator.valid_until
            else None
        )

        indicator_properties = {
            "severity": xdr_severity,
            "expiration_date": xdr_expiration_timestamp,
            "comment": octi_indicator.description,
            "reputation": "BAD",  # intentionally hardcoded for now
            "reliability": None,  # intentionally non-set for now
        }

        # Map observables' fields and build Cortex XDR IOCs
        xdr_iocs: list[CortexXdrIoc] = []
        for observable in octi_indicator.observables:
            if observable.type.lower() == "stixfile":
                # Only hashes are mapped for now; filename is intentionally out of scope (currently commented)
                # if observable.name:
                #     xdr_iocs.append(
                #         CortexXdrIoc(
                #             type="FILENAME",
                #             indicator=observable.name,
                #             **indicator_properties,
                #         )
                #     )
                if observable.hashes:
                    for hash_value in observable.hashes.values():
                        xdr_iocs.append(
                            CortexXdrIoc(
                                type="HASH",
                                indicator=hash_value,
                                **indicator_properties,
                            )
                        )
            elif observable.type.lower() in ("domain-name", "hostname"):
                xdr_iocs.append(
                    CortexXdrIoc(
                        type="DOMAIN_NAME",
                        indicator=observable.value,  # type: ignore[union-attr]  # `value` is always set for DomainName/Hostname observables
                        **indicator_properties,
                    )
                )
            elif observable.type.lower() in ("ipv4-addr", "ipv6-addr"):
                xdr_iocs.append(
                    CortexXdrIoc(
                        type="IP",
                        indicator=observable.value,  # type: ignore[union-attr]  # `value` is always set for IP observables
                        **indicator_properties,
                    )
                )

        return xdr_iocs

    def _resolve_xdr_iocs_rule_ids(
        self, extracted_xdr_iocs: list[CortexXdrIoc]
    ) -> list[CortexXdrIoc]:
        """Resolve `rule_id` for each Cortex XDR IOC extracted from the indicator's observables."""
        if not extracted_xdr_iocs:
            return []

        # Look up existing IOCs on Cortex XDR
        result = self.client.get_iocs(
            [
                {
                    "field": "indicator",
                    "operator": "IN",
                    "value": [ioc.indicator for ioc in extracted_xdr_iocs],
                }
            ]
        )
        existing_xdr_iocs = result.get("objects", [])

        # Attach `rule_id` to each extracted IOC that already exists on Cortex XDR
        for ioc in extracted_xdr_iocs:
            existing_ioc = next(
                (
                    existing_ioc
                    for existing_ioc in existing_xdr_iocs
                    if existing_ioc["indicator"] == ioc.indicator
                    and existing_ioc["type"] == ioc.type
                ),
                None,
            )
            if existing_ioc:
                ioc.rule_id = existing_ioc.get("rule_id")

        return extracted_xdr_iocs  # type: ignore[return-value]  # `rule_id` (int) is added to each dict

    def _handle_upsert(self, octi_indicator: OctiIndicator) -> None:
        """Upsert `octi_indicator`'s supported observables into Cortex XDR as IOCs."""
        # Extract Cortex XDR IOCs from the indicator's observables
        xdr_iocs = self._extract_xdr_iocs(octi_indicator)
        xdr_iocs = self._resolve_xdr_iocs_rule_ids(xdr_iocs)
        if not xdr_iocs:
            self.helper.connector_logger.error(
                "No Cortex XDR IOC could be extracted from any observable, "
                "skipping indicator",
                {
                    "indicator_id": octi_indicator.id,
                    "observables_count": len(octi_indicator.observables),
                },
            )
            return

        self.helper.connector_logger.debug(
            "Upserting indicator(s) into Cortex XDR",
            {"indicator_id": octi_indicator.id, "xdr_iocs": len(xdr_iocs)},
        )

        # Send the payloads to Cortex XDR as dicts, omitting any unset fields to let client default them.
        self.client.insert_iocs(
            [ioc.model_dump(exclude_none=True) for ioc in xdr_iocs]  # type: ignore[arg-type]
        )

        self.helper.connector_logger.info(
            "Successfully upserted indicator(s) into Cortex XDR",
            {"indicator_id": octi_indicator.id, "xdr_iocs": len(xdr_iocs)},
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
            octi_indicator = self._build_octi_indicator(entity_data)
            if not octi_indicator.observables:
                self.helper.connector_logger.warning(
                    "No supported observable(s) found in indicator, skipping it",
                    {
                        "event": event,
                        "indicator_id": octi_indicator.id,
                        "observables_count": len(octi_indicator.observables),
                    },
                )
                return

            self.helper.connector_logger.info(
                "Parsed observable(s) from stream event",
                {
                    "event": event,
                    "indicator_id": octi_indicator.id,
                    "observables_count": len(octi_indicator.observables),
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
                self._handle_upsert(octi_indicator)
            elif event == "delete":
                pass  # TODO: delete from Cortex XDR (#7187)

        except CortexXdrApiError as err:
            fatal_causes = (
                ApiUnauthorizedError,  # 401
                ApiForbiddenError,  # 403
                ApiNotFoundError,  # 404
                ApiRateLimitError,  # 429
                ApiServerError,  # 5xx
            )

            if err.__cause__ and isinstance(err.__cause__, fatal_causes):
                # The process must be **killed to avoid exhausting** the stream with repeated global failure e.g.,
                # invalid/revoked API key, rate limit exceeded, API breaking changes, etc.
                self.helper.connector_logger.error(
                    f"Error while hitting Cortex XDR API.\n{self._exit_message}",
                    {
                        "event": event,
                        "entity_data": entity_data,
                        "error": err,
                    },
                )
                raise  # let `pycti` kill the connector process
            else:
                # The process must **continue to avoid blocking** the stream with a failure scoped to one specific event
                # (e.g., rejected IOC value) so the next event get a chance to be processed.
                self.helper.connector_logger.error(
                    "Error while hitting Cortex XDR API. Skipping event and continuing with the next one.",
                    {
                        "event": event,
                        "entity_data": entity_data,
                        "error": err,
                    },
                )
                return  # skip the event and continue
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
