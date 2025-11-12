import json
import sys
import traceback

from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel.client import ConnectorClient
from microsoft_sentinel_intel.config import ConnectorSettings
from microsoft_sentinel_intel.errors import (
    ConnectorError,
    ConnectorWarning,
)
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
            self.helper.connector_logger.error(
                message=err.message,
                meta=err.metadata,
            )
        except Exception as err:
            traceback.print_exc()
            self.helper.connector_logger.error(
                message=f"Unexpected error: {err}",
                meta={"error": str(err)},
            )

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
