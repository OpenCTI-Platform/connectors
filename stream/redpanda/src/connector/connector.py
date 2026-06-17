import json

from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from redpanda_client import RedpandaClient


class RedpandaConnector:
    """
    Specifications of the Redpanda stream connector.

    This connector listens to an OpenCTI live stream and publishes every event
    (create, update, delete) to a Redpanda topic through the Redpanda HTTP Proxy,
    so downstream consumers can react to threat intelligence changes in real time.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `RedpandaConnector` with its configuration.

        :param config: Configuration of the connector.
        :param helper: Helper to manage connection and requests to OpenCTI.
        """
        self.config = config
        self.helper = helper
        self.client = RedpandaClient(config, helper)

    def check_stream_id(self) -> None:
        """Raise a ValueError if the live stream ID is missing or left as a placeholder."""
        stream_id = self.helper.connect_live_stream_id
        if (
            stream_id is None
            or not str(stream_id).strip()
            or str(stream_id).strip().lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def process_message(self, msg) -> None:
        """
        Process a single message coming from the OpenCTI live stream.

        :param msg: Message event from the stream.
        """
        try:
            data = json.loads(msg.data)["data"]
        except (json.JSONDecodeError, KeyError, TypeError) as err:
            raise ValueError(f"Cannot process the message: {err}") from err

        if self.client.produce_event(msg.event, data):
            # Per-event write logged at DEBUG: live streams are high-volume, so
            # an INFO line per event would flood logs and add IO overhead.
            self.helper.connector_logger.debug(
                "[%s] Event produced to Redpanda topic" % msg.event.upper()
            )

    def run(self) -> None:
        """Validate the live stream id, then listen to the OpenCTI live stream."""
        self.check_stream_id()
        self.helper.listen_stream(message_callback=self.process_message)
