# import json

from pycti import OpenCTIConnectorHelper
from template_client import TemplateClient

from .settings import ConnectorSettings


class TemplateConnector:
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
        converter_to_stix (ConnectorConverter):
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message

    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize `TemplateConnector` with its configuration.

        Args:
            config (ConnectorSettings): Configuration of the connector
            helper (OpenCTIConnectorHelper): Helper to manage connection and requests to OpenCTI
        """
        self.config = config
        self.helper = helper

        self.client = TemplateClient(
            helper,
            base_url=self.config.template.api_base_url,
            api_key=self.config.template.api_key,
            # Pass any arguments necessary to the client
        )

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
        :return: string
        """
        try:
            self.check_stream_id()

            # data = json.loads(msg.data)["data"]
        except Exception:
            raise ValueError("Cannot process the message")

        # Performing the main process
        # ===========================
        # === Add your code below ===
        # ===========================

        # EXAMPLE
        # Handle creation
        if msg.event == "create":
            self.helper.connector_logger.info("[CREATE]")
            # Do something
            raise NotImplementedError

        # Handle update
        if msg.event == "update":
            self.helper.connector_logger.info("[UPDATE]")
            # Do something
            raise NotImplementedError

        # Handle delete
        if msg.event == "delete":
            self.helper.connector_logger.info("[DELETE]")
            # Do something
            raise NotImplementedError

        # ===========================
        # === Add your code above ===
        # ===========================

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
