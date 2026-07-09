import json

from connector.settings import ConnectorSettings
from connector.utils import indicator_type_for_event, is_valid_event
from datadog_intel_client import DatadogIntelClient
from pycti import OpenCTIConnectorHelper


class DatadogIntelConnector:
    """
    Specifications of the stream connector:

    This class encapsulates the main actions, expected to be run by any connector of type `STREAM`.
    This type of connector has the capability to listen to live streams from the OpenCTI platform.
    It is highly useful for creating connectors that can react and make decisions in real time.
    Actions on OpenCTI will apply the changes to the third-party connected platform.

    ---

    Attributes:
        config (ConnectorSettings):
            Store the connector's configuration. It defines how to connector will behave.
        helper (OpenCTIConnectorHelper):
            Handle the connection and the requests between the connector, OpenCTI and the workers.
            _All connectors MUST use the connector helper with connector's configuration._
        client (DatadogIntelClient):
            Provide methods to request the external API.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message

    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `DatadogIntelConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.clients: dict[str, DatadogIntelClient] = {
            ind_type: DatadogIntelClient(
                helper=helper, config=config, indicator_type=ind_type
            )
            for ind_type in config.datadog_intel.indicator_type
        }

    def check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: None
        """
        self.helper.connector_logger.debug(
            "Message received", meta={"event": msg.event, "id": msg.id}
        )
        try:
            self.check_stream_id()
            data = json.loads(msg.data)["data"]
            data["event_type"] = msg.event
            data["x_opencti_event_type"] = msg.event
        except Exception as e:
            self.helper.connector_logger.error(
                "Cannot parse message", meta={"error": str(e), "raw": msg.data}
            )
            return

        self.helper.connector_logger.debug("Message parsed", meta={"data": data})

        if not is_valid_event(data, self.helper, self.config):
            return

        ind_type = indicator_type_for_event(data)
        if ind_type is None:
            self.helper.connector_logger.debug(
                "Skipping indicator with unknown type",
                meta={"id": data.get("id"), "raw": data},
            )
            return

        client = self.clients.get(ind_type)
        if client is None:
            self.helper.connector_logger.debug(
                "Skipping indicator type not configured",
                meta={"indicator_type": ind_type, "id": data.get("id")},
            )
            return

        client.process_indicator(data)

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
