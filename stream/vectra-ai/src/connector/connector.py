import json

from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from vectra_client import VectraClient


class VectraAIConnector:
    """
    Specifications of the Vectra AI stream connector.

    This connector listens to an OpenCTI live stream and forwards indicators of
    compromise (IOCs) to a managed Vectra AI threat feed in real time. Supported
    observables are IP addresses (IPv4/IPv6), domain names and URLs.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `VectraAIConnector` with its configuration.

        :param config: Configuration of the connector.
        :param helper: Helper to manage connection and requests to OpenCTI.
        """
        self.config = config
        self.helper = helper
        self.client = VectraClient(config, helper)

    def check_stream_id(self) -> None:
        """Raise a ValueError if the live stream ID is missing."""
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _handle_indicator(self, event: str, data: dict) -> None:
        if data.get("type") != "indicator" or data.get("pattern_type") != "stix":
            return

        if event in ("create", "update"):
            if self.client.add_indicator(data):
                self.helper.connector_logger.info(
                    "[%s] Indicator pushed to Vectra AI threat feed" % event.upper()
                )
        elif event == "delete":
            self.helper.connector_logger.debug(
                "[DELETE] Vectra threat feeds do not support per-indicator deletion; "
                "the indicator will expire automatically based on the feed duration"
            )

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

        self._handle_indicator(msg.event, data)

    def run(self) -> None:
        """Start listening to the OpenCTI live stream."""
        self.helper.listen_stream(message_callback=self.process_message)
