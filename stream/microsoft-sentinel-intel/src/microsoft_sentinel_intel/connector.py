import json
import sys
import traceback
from typing import Any

from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel.client import ConnectorClient
from microsoft_sentinel_intel.errors import ConnectorError, ConnectorWarning
from microsoft_sentinel_intel.settings import ConnectorSettings
from microsoft_sentinel_intel.utils import is_stix_indicator
from pycti import OpenCTIConnectorHelper


class Connector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConnectorSettings,
        client: ConnectorClient,
    ) -> None:
        self.helper = helper
        self.config = config
        self.client = client

    def _prepare_stix_object(self, stix_object: dict) -> dict:
        if self.config.microsoft_sentinel_intel.delete_extensions:
            del stix_object["extensions"]
        if extra_labels := self.config.microsoft_sentinel_intel.extra_labels:
            stix_object["labels"] = list(
                set(stix_object.get("labels", []) + extra_labels)
            )
        return stix_object

    def _process_event(self, event_type: str, stix_object: dict) -> None:
        """
        This method can handle any type of event with the same logic (_prepare_stix_object)

        The API used (upload_stix_objects) to upload the stix objects to Sentinel can handle
          Indicators, AttackPatterns, Identity, ThreatActors and Relationships.
        """
        match event_type:
            case "create" | "update":
                self.client.upload_stix_objects(
                    stix_objects=[self._prepare_stix_object(stix_object)],
                    source_system=self.config.microsoft_sentinel_intel.source_system,
                )
            case "delete":
                self.client.delete_indicator_by_id(stix_object["id"])
            case _:
                raise ConnectorWarning(
                    message=f"Unsupported event type: {event_type}, Skipping..."
                )

    def _handle_event(self, event: Event):
        try:
            data = json.loads(event.data)["data"]
        except json.JSONDecodeError as err:
            raise ConnectorError(
                message="[ERROR] Data cannot be parsed to JSON",
                metadata={"message_data": event.data, "error": str(err)},
            ) from err
        if is_stix_indicator(data):
            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] Processing message",
                meta={"data": data, "event": event.event},
            )
            self._process_event(event_type=event.event, stix_object=data)
            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] Indicator processed",
                meta={"opencti_id": data["id"]},
            )
        else:
            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] Entity not supported"
            )

    def process_message(self, message: Event) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param message: Message event from stream
        :return: string
        """
        try:
            self._handle_event(message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped by user.")
            sys.exit(0)
        except ConnectorWarning as err:
            self.helper.connector_logger.warning(message=err.message)
        except ConnectorError as err:
            self.helper.connector_logger.error(message=err.message, meta=err.metadata)
        except Exception as err:
            traceback.print_exc()
            self.helper.connector_logger.error(
                message=f"Unexpected error: {err}", meta={"error": str(err)}
            )

    def _parse_event(self, event: Event) -> dict[str, Any] | None:
        """Parse a stream event and return a dict with event_type and data, or None if not processable."""
        try:
            data = json.loads(event.data)["data"]
        except json.JSONDecodeError as err:
            self.helper.connector_logger.error(
                message="[ERROR] Data cannot be parsed to JSON",
                meta={"message_data": event.data, "error": str(err)},
            )
            return None
        if not is_stix_indicator(data):
            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] Entity not supported"
            )
            return None
        return {"event_type": event.event, "data": data}

    def process_message_batch(self, batch_data: dict) -> None:
        """
        Process a batch of stream events.
        Accumulates create/update indicators and uploads them in a single API call.
        Delete events are processed individually.

        :param batch_data: Dictionary with "events" list and "batch_metadata"
        """
        events = batch_data["events"]
        batch_metadata = batch_data["batch_metadata"]

        self.helper.connector_logger.info(
            message="[BATCH] Processing batch",
            meta={
                "batch_size": batch_metadata["batch_size"],
                "trigger": batch_metadata["trigger_reason"],
            },
        )

        stix_objects_to_upload: list[dict] = []
        delete_ids: list[dict] = []

        for event in events:
            try:
                parsed = self._parse_event(event)
                if parsed is None:
                    continue

                event_type = parsed["event_type"]
                stix_object = parsed["data"]

                match event_type:
                    case "create" | "update":
                        stix_objects_to_upload.append(
                            self._prepare_stix_object(stix_object)
                        )
                    case "delete":
                        delete_ids.append(stix_object)
                    case _:
                        self.helper.connector_logger.warning(
                            message=f"Unsupported event type: {event_type}, Skipping..."
                        )
            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("Connector stopped by user.")
                sys.exit(0)
            except Exception as err:
                self.helper.connector_logger.error(
                    message=f"[BATCH] Error parsing event: {err}",
                    meta={"error": str(err)},
                )

        # Bulk upload create/update indicators in chunks of MAX_STIX_OBJECTS_PER_REQUEST
        batch_size = self.config.microsoft_sentinel_intel.batch_size
        if stix_objects_to_upload:
            for i in range(0, len(stix_objects_to_upload), batch_size):
                chunk = stix_objects_to_upload[i : i + batch_size]
                try:
                    self.client.upload_stix_objects(
                        stix_objects=chunk,
                        source_system=self.config.microsoft_sentinel_intel.source_system,
                    )
                    self.helper.connector_logger.info(
                        message="[BATCH] Indicators uploaded",
                        meta={
                            "count": len(chunk),
                            "chunk": f"{i // batch_size + 1}",
                            "total": len(stix_objects_to_upload),
                        },
                    )
                except Exception as err:
                    self.helper.connector_logger.error(
                        message=f"[BATCH] Failed to upload indicators: {err}",
                        meta={
                            "error": str(err),
                            "count": len(chunk),
                            "total": len(stix_objects_to_upload),
                        },
                    )
                    raise

        # Process deletes individually (delete API requires individual calls)
        for stix_object in delete_ids:
            try:
                self.client.delete_indicator_by_id(stix_object["id"])
                self.helper.connector_logger.info(
                    message="[BATCH] Indicator deleted",
                    meta={"opencti_id": stix_object["id"]},
                )
            except Exception as err:
                self.helper.connector_logger.error(
                    message=f"[BATCH] Failed to delete indicator: {err}",
                    meta={
                        "error": str(err),
                        "opencti_id": stix_object["id"],
                    },
                )
                raise

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        sentinel_config = self.config.microsoft_sentinel_intel
        batch_size = sentinel_config.batch_size
        batch_timeout = sentinel_config.batch_timeout
        max_per_minute = sentinel_config.max_per_minute

        if batch_size or batch_timeout:
            batch_callback = self.helper.create_batch_callback(
                batch_callback=self.process_message_batch,
                batch_size=batch_size,
                batch_timeout=batch_timeout,
                max_per_minute=max_per_minute,
            )
            self.helper.listen_stream(message_callback=batch_callback)
        else:
            self.helper.listen_stream(message_callback=self.process_message)
