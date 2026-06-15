import json

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
        """Raise a ValueError if the live stream ID is missing."""
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def process_message(self, msg) -> None:
        """
        Process a single message coming from the OpenCTI live stream.

        :param msg: Message event from the stream.
        """
        self.check_stream_id()

        try:
            data = json.loads(msg.data)["data"]
        except Exception as err:
            raise ValueError(f"Cannot process the message: {err}")

        if self.client.insert_event(msg.event, data):
            self.helper.connector_logger.info(
                "[%s] Event written to ClickHouse" % msg.event.upper()
            )

    def run(self) -> None:
        """Ensure the ClickHouse schema exists then listen to the OpenCTI live stream."""
        self.client.ensure_table()
        self.helper.listen_stream(message_callback=self.process_message)
