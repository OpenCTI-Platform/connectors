import json
import sys
import traceback

from filigran_sseclient.sseclient import Event
from microsoft_sentinel_intel.client import ConnectorClient
from microsoft_sentinel_intel.config import ConnectorSettings
from microsoft_sentinel_intel.errors import (
    ConnectorConfigError,
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

    def _check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ConnectorConfigError(
                "Missing stream ID, please check your configurations."
            )

    def _process_event(self, event_type: str, indicator: dict) -> None:
        match event_type:
            case "create" | "update":
                self.client.post_indicator(indicator)
            case "delete":
                self.client.delete_indicator(indicator["id"])
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
            self._process_event(event_type=event.event, indicator=data)

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
            self._check_stream_id()
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
        self.helper.set_state({})
        self.helper.listen_stream(message_callback=self.process_message)
