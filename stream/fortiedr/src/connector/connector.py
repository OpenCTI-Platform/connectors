import json

from connector.settings import ConnectorSettings
from fortiedr_client import FortiEDRClient
from pycti import OpenCTIConnectorHelper


class FortiEDRConnector:
    """
    Specifications of the FortiEDR stream connector.

    This connector listens to an OpenCTI live stream and synchronises IP
    indicators (IPv4/IPv6) to a managed FortiEDR IP Set in real time. Other
    observable types are best ingested through FortiEDR's native STIX/TAXII
    Threat Intelligence Feed (see README).
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `FortiEDRConnector` with its configuration.

        :param config: Configuration of the connector.
        :param helper: Helper to manage connection and requests to OpenCTI.
        """
        self.config = config
        self.helper = helper
        self.client = FortiEDRClient(config, helper)

    def check_stream_id(self) -> None:
        """Raise a ValueError if the live stream ID is missing or left as a placeholder."""
        stream_id = self.helper.connect_live_stream_id
        if (
            stream_id is None
            or not str(stream_id).strip()
            or str(stream_id).strip().lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _handle_indicator(self, event: str, data: dict) -> None:
        if data.get("type") != "indicator" or data.get("pattern_type") != "stix":
            return

        if event in ("create", "update"):
            if self.client.add_indicator(data):
                self.helper.connector_logger.info(
                    "[%s] IP indicator synced to FortiEDR IP Set" % event.upper()
                )
        elif event == "delete":
            if self.client.remove_indicator(data):
                self.helper.connector_logger.info(
                    "[DELETE] IP indicator removed from FortiEDR IP Set"
                )

    def process_message(self, msg) -> None:
        """
        Process a single message coming from the OpenCTI live stream.

        :param msg: Message event from the stream.
        """
        try:
            data = json.loads(msg.data)["data"]
        except (json.JSONDecodeError, KeyError, TypeError) as err:
            raise ValueError(f"Cannot process the message: {err}") from err

        self._handle_indicator(msg.event, data)

    def run(self) -> None:
        """Validate the live stream id, then listen to the OpenCTI live stream."""
        self.check_stream_id()
        self.helper.listen_stream(message_callback=self.process_message)
