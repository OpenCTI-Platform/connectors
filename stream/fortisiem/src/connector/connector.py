import json

from connector.settings import ConnectorSettings
from fortisiem_client import FortiSIEMClient
from pycti import OpenCTIConnectorHelper


class FortiSIEMConnector:
    """
    Specifications of the FortiSIEM stream connector.

    This connector listens to an OpenCTI live stream and adds indicators
    (IPv4/IPv6, domain names, URLs and file hashes) to a FortiSIEM Watch List in
    real time. Watch List entries expire automatically through the configured
    age-out.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `FortiSIEMConnector` with its configuration.

        :param config: Configuration of the connector.
        :param helper: Helper to manage connection and requests to OpenCTI.
        """
        self.config = config
        self.helper = helper
        self.client = FortiSIEMClient(config, helper)

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
                    "[%s] Indicator added to FortiSIEM Watch List" % event.upper()
                )
        elif event == "delete":
            self.helper.connector_logger.debug(
                "[DELETE] FortiSIEM Watch List entries expire through their age-out; "
                "no explicit delete is performed"
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
        """Validate the stream id, then listen to the OpenCTI live stream."""
        self.check_stream_id()
        self.helper.listen_stream(message_callback=self.process_message)
