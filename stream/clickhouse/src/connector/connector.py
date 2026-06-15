import json
import time

from clickhouse_client import ClickHouseClient
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class ClickHouseConnector:
    """
    Specifications of the ClickHouse stream connector.

    This connector listens to an OpenCTI live stream and writes every event
    (create, update, delete) to a ClickHouse table through the ClickHouse HTTP
    interface, making OpenCTI knowledge available for analytics and hunting.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `ClickHouseConnector` with its configuration.

        :param config: Configuration of the connector.
        :param helper: Helper to manage connection and requests to OpenCTI.
        """
        self.config = config
        self.helper = helper
        self.client = ClickHouseClient(config, helper)

    def check_stream_id(self) -> None:
        """Raise a ValueError if the live stream ID is missing or left as a placeholder."""
        stream_id = self.helper.connect_live_stream_id
        if (
            stream_id is None
            or not str(stream_id).strip()
            or str(stream_id).strip().lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    @staticmethod
    def _event_timestamp(msg) -> int:
        """
        Return the OpenCTI event time as a Unix timestamp (seconds).

        OpenCTI live-stream event ids are Redis stream ids of the form
        ``<milliseconds>-<sequence>``, so the event time is derived from the id
        prefix. Falls back to the connector receipt time when the id is missing
        or cannot be parsed.
        """
        event_id = getattr(msg, "id", None)
        if event_id:
            try:
                return int(str(event_id).split("-")[0]) // 1000
            except (ValueError, TypeError):
                pass
        return int(time.time())

    def process_message(self, msg) -> None:
        """
        Process a single message coming from the OpenCTI live stream.

        :param msg: Message event from the stream.
        """
        self.check_stream_id()

        try:
            data = json.loads(msg.data)["data"]
        except (json.JSONDecodeError, KeyError, TypeError) as err:
            raise ValueError(f"Cannot process the message: {err}") from err

        if self.client.insert_event(msg.event, data, self._event_timestamp(msg)):
            self.helper.connector_logger.info(
                "[%s] Event written to ClickHouse" % msg.event.upper()
            )

    def run(self) -> None:
        """Ensure the ClickHouse schema exists then listen to the OpenCTI live stream."""
        if not self.client.ensure_table():
            raise RuntimeError(
                "Failed to ensure the ClickHouse schema exists; aborting startup."
            )
        self.helper.listen_stream(message_callback=self.process_message)
