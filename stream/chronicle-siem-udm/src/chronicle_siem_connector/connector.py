import json

from pycti import OpenCTIConnectorHelper

from .api_client import ChronicleEntitiesClient
from .config_variables import ConfigConnector
from .cti_converter import CTIConverter


class ChronicleSIEMConnector:
    """
    Specifications of the Stream connector

    This class encapsulates the main actions, expected to be run by any stream connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector has the capability to listen to live streams from the OpenCTI platform.
    It is highly useful for creating connectors that can react and make decisions in real time.
    Actions on OpenCTI will apply the changes to the third-party connected platform
    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

    ---

    Best practices
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message

    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.converter = CTIConverter(self.helper, self.config)
        self.api_client = ChronicleEntitiesClient(self.helper, self.config)

    def check_stream_id(self):
        """
        In case of stream_id configuration is missing, raise ValueError
        """
        if (
            not self.helper.connect_live_stream_id
            or self.helper.connect_live_stream_id.lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _handle_upsert(self, data: dict, event_context: dict = None):
        """
        Handle `create` or `update` event.
        :param data: Data streamed by OpenCTI
        :param event_context: Additional context for `update` event (optional)
        """

        if data["type"] == "indicator" and data["pattern_type"].startswith("stix"):

            self.helper.connector_logger.info(
                f"{'[UPDATE]' if event_context else '[CREATE]'} Indicator",
                {"indicator_id": data["id"]},
            )
            self._upsert_ioc_rule(data)

    def _upsert_ioc_rule(self, indicator):
        """
        Convert each indicator's observable to a UDM entity and upsert it in Chronicle.
        :param indicator: Indicator to upsert
        """
        udm_entities = self.converter.create_udm_entity(indicator)
        self.api_client.ingest(udm_entities)

    def process_message(self, msg):
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        """
        self.check_stream_id()

        try:
            parsed_msg = json.loads(msg.data)
        except json.JSONDecodeError:
            self.helper.connector_logger.error(
                "[ERROR] Cannot parse message's data", {"msg_data": msg.data}
            )
            return

        data = parsed_msg["data"]

        context = parsed_msg["context"] if "context" in parsed_msg else None

        match msg.event:
            case "create":
                self._handle_upsert(data)
            case "update":
                self._handle_upsert(data, context)

    def run(self):
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
