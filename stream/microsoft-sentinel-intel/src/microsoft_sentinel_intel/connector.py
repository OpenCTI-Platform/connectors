import json
import sys
import traceback

from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel.client import ConnectorClient
from microsoft_sentinel_intel.errors import (
    ConnectorClientError,
    ConnectorError,
    ConnectorWarning,
)
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
        stix_object = dict(stix_object)
        if self.config.microsoft_sentinel_intel.delete_extensions:
            stix_object.pop("extensions", None)
        if extra_labels := self.config.microsoft_sentinel_intel.extra_labels:
            stix_object["labels"] = list(
                set(stix_object.get("labels", []) + extra_labels)
            )
        return stix_object

    def _process_event(self, event_type: str, stix_object: dict) -> bool:
        """Process a single STIX event by dispatching to the appropriate API call.

        The upload API (upload_stix_objects) handles Indicators, AttackPatterns,
        Identity, ThreatActors, and Relationships.

        :param event_type: One of "create", "update", or "delete".
        :param stix_object: STIX object data dict.
        :return: True if the event was processed, False if filtered out by event_types config.
        :raises ConnectorClientError: If the API call fails.
        :raises ConnectorWarning: If event_type is unsupported.
        """
        if event_type not in self.config.microsoft_sentinel_intel.event_types:
            self.helper.connector_logger.info(
                message=f"[{event_type.upper()}] Event type filtered out, skipping"
            )
            return False

        match event_type:
            case "create" | "update":
                prepared = self._prepare_stix_object(stix_object)
                self.client.upload_stix_objects(
                    stix_objects=[prepared],
                    source_system=self.config.microsoft_sentinel_intel.source_system,
                )
            case "delete":
                self.client.delete_indicator_by_id(
                    stix_object["id"],
                    source_system=self.config.microsoft_sentinel_intel.source_system,
                )
            case _:
                raise ConnectorWarning(
                    message=f"Unsupported event type: {event_type}, Skipping..."
                )
        return True

    def _handle_event(self, event: Event):
        try:
            parsed = json.loads(event.data)
        except json.JSONDecodeError as err:
            raise ConnectorError(
                message="[ERROR] Data cannot be parsed to JSON",
                metadata={"message_data": event.data, "error": str(err)},
            ) from err

        data = parsed.get("data")
        if not data:
            return

        if is_stix_indicator(data):
            self.helper.connector_logger.info(
                message=f"[{event.event.upper()}] Processing message",
                meta={"data": data, "event": event.event},
            )
            processed = self._process_event(event_type=event.event, stix_object=data)
            if processed:
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

    def process_batch(self, batch_data: dict) -> None:
        """
        Batch callback for SDK BatchCallbackWrapper.
        Receives a dict with "events" (list of raw SSE messages) and processes them
        as a single batch upload.
        """
        try:
            events = batch_data.get("events", [])
            if not events:
                return

            unique_objects: dict[str, tuple[str, dict]] = {}
            for event in events:
                try:
                    parsed = json.loads(event.data)
                except json.JSONDecodeError as err:
                    self.helper.connector_logger.error(
                        message="[BATCH] Data cannot be parsed to JSON",
                        meta={"message_data": event.data, "error": str(err)},
                    )
                    continue

                data = parsed.get("data")
                if not data:
                    continue

                if not is_stix_indicator(data):
                    continue

                if event.event not in self.config.microsoft_sentinel_intel.event_types:
                    continue

                unique_objects[data["id"]] = (event.event, data)

            if not unique_objects:
                return

            objects_to_upload = []
            objects_to_delete = []
            for event_type, data in unique_objects.values():
                if event_type in ("create", "update"):
                    objects_to_upload.append(data)
                elif event_type == "delete":
                    objects_to_delete.append(data)

            if objects_to_upload:
                prepared_objects = [
                    self._prepare_stix_object(obj) for obj in objects_to_upload
                ]
                self.helper.connector_logger.info(
                    message=f"[BATCH] Uploading {len(prepared_objects)} objects",
                )
                self.client.upload_stix_objects(
                    stix_objects=prepared_objects,
                    source_system=self.config.microsoft_sentinel_intel.source_system,
                )

            for data in objects_to_delete:
                try:
                    self.helper.connector_logger.info(
                        message="[BATCH] Deleting indicator",
                        meta={"opencti_id": data["id"]},
                    )
                    self.client.delete_indicator_by_id(
                        data["id"],
                        source_system=self.config.microsoft_sentinel_intel.source_system,
                    )
                except ConnectorClientError as err:
                    self.helper.connector_logger.error(
                        message=f"[BATCH] Failed to delete indicator {data['id']}",
                        meta=err.metadata,
                    )
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
                message=f"[BATCH] Unexpected error: {err}",
                meta={"error": str(err)},
            )

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        if self.config.microsoft_sentinel_intel.batch_mode:
            self.helper.connector_logger.info(
                message=f"[BATCH] Batch mode enabled (batch_size={self.config.microsoft_sentinel_intel.batch_size}, batch_timeout={self.config.microsoft_sentinel_intel.batch_timeout}s, max_per_minute=100)",
            )
            callback = self.helper.create_batch_callback(
                batch_callback=self.process_batch,
                batch_size=self.config.microsoft_sentinel_intel.batch_size,
                batch_timeout=self.config.microsoft_sentinel_intel.batch_timeout,
                # Azure Sentinel Upload Indicators API is limited to 100 requests/min
                max_per_minute=100,
            )
            self.helper.listen_stream(message_callback=callback)
        else:
            self.helper.listen_stream(message_callback=self.process_message)
