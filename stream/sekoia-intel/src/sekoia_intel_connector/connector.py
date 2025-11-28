import json

from pycti import OpenCTIConnectorHelper

from .api_client import SekoiaClient
from .config_variables import ConfigConnector
from .cti_converter import CTIConverter
from .models import opencti


class SekoiaIntelConnector:
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
        self.stix_converter = CTIConverter(self.config)
        self.api_client = SekoiaClient(self.helper, self.config)

    def check_stream_id(self):
        """
        In case of stream_id configuration is missing, raise ValueError
        """
        if (
            not self.helper.connect_live_stream_id
            or self.helper.connect_live_stream_id.lower() == "changeme"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _instantiate_indicator(self, data: dict) -> opencti.Indicator | None:
        """
        Get indicator's available additional data and create an OpenCTI Indicator instance.
        :param data: Data streamed by OpenCTI
        :return: Indicator instance
        """
        if data["type"] != "indicator":
            return None

        return opencti.Indicator(data, self.helper.opencti_url)

    def _handle_upsert(self, data: dict, update: bool = False):
        """
        Handle `create` or `update` event.
        :param data: Data streamed by OpenCTI
        :param update: Whether the event is an update or a creation
        """
        indicator = self._instantiate_indicator(data)
        if indicator is None:
            return

        self.helper.connector_logger.info(
            f"{'[UPDATE]' if update else '[CREATE]'} Indicator",
            {"indicator_id": indicator.id},
        )

        if indicator.pattern_type == "stix":
            self._upsert_ioc_rule(indicator)

    def _upsert_ioc_rule(self, indicator: opencti.Indicator):
        """
        Convert each indicator's observable to an IOC rule and upsert it in Sekoia collection.
        :param indicator: Indicator to upsert IOC rules for
        """
        if indicator.revoked:
            return self._delete_ioc_rule(indicator)

        try:
            sekoia_indicator = self.stix_converter.create_sekoia_ioc(indicator)
            if sekoia_indicator is not None:
                self.api_client.send_ioc_in_collection(sekoia_indicator)
        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Error while creating or sending ioc: ",
                {"error": str(err)},
            )

    def _handle_delete(self, data: dict):
        """
        Handle `delete` event.
        :param data: Data streamed by OpenCTI
        """
        indicator = self._instantiate_indicator(data)
        if indicator is None or indicator.pattern_type != "stix":
            return None

        self.helper.connector_logger.info(
            "[DELETE] Indicator", {"indicator_id": indicator.id}
        )
        self._delete_ioc_rule(indicator)

    def _delete_ioc_rule(self, indicator: opencti.Indicator):
        """
        Convert indicator to an IOC rule and revoke it from Sekoia.io.
        :param indicator: Indicator to revoke IOC rule for
        """
        try:
            sekoia_indicator = self.stix_converter.create_sekoia_ioc(indicator)
            if sekoia_indicator is not None:
                self.api_client.delete_iocs_in_collection(sekoia_indicator)
        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Error while revoking ioc: ",
                {"error": str(err)},
            )

    def process_message(self, msg):
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        """
        try:
            parsed_msg = json.loads(msg.data)
        except json.JSONDecodeError:
            self.helper.connector_logger.error(
                "[ERROR] Cannot parse message's data", {"msg_data": msg.data}
            )
            return

        data = parsed_msg["data"]

        match msg.event:
            case "create":
                self._handle_upsert(data)
            case "update":
                self._handle_upsert(data, update=True)
            case "delete":
                self._handle_delete(data)

    def run(self):
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.check_stream_id()
        self.helper.listen_stream(message_callback=self.process_message)
