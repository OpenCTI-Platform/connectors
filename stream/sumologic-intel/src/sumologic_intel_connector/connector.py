import json
from json import JSONDecodeError

from pycti import OpenCTIConnectorHelper

from .config_loader import ConfigConnector
from .api_client import SumologicClient
from .utils import is_stix_indicator


class SumologicIntelConnector:
    """
    """

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """
        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.sumologic_client = SumologicClient(self.helper, self.config)
        self.source_name = "OpenCTI"

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


    def validate_json(self, msg) -> dict | JSONDecodeError:
        """
        Validate the JSON data from the stream
        :param msg: Message event from stream
        :return: Parsed JSON data or raise JSONDecodeError if JSON data cannot be parsed
        """
        try:
            parsed_msg = json.loads(msg.data)
            return parsed_msg
        except json.JSONDecodeError:
            self.helper.connector_logger.error(
                "[ERROR] Data cannot be parsed to JSON", {"msg_data": msg.data}
            )
            raise JSONDecodeError("Data cannot be parsed to JSON", msg.data, 0)

    def _handle_create_update_event(self, data):
        """
        Handle create/update event by publishing the corresponding Threat Intelligence Indicator on Sumologic.
        :param data: Streamed data (representing either an observable or an indicator)
        """
        if is_stix_indicator(data):
            self.sumologic_client.upload_stix_indicator(source_name=self.source_name, stix_indicator=data)
        else:
            if data.get("type") == "indicator":
                msg = f"Indicator of pattern type: {data.get('pattern_type')} not supported"
            else:
                msg = f"Entity type: {data.get('type')} not supported"

            self.helper.connector_logger.warning(
                message=msg
            )

    def _handle_delete_event(self, data):
        """
        Handle delete event by deleting the corresponding Threat Intelligence Indicator on Sumologic.
        :param data: Streamed data (representing either an observable or an indicator)
        """
        if is_stix_indicator(data):
            self.sumologic_client.delete_stix_indicator(source_name=self.source_name, stix_indicator=data)
        else:
            if data.get("type") == "indicator":
                msg = f"Indicator of pattern type: {data.get('pattern_type')} not supported"
            else:
                msg = f"Entity type: {data.get('type')} not supported"

            self.helper.connector_logger.warning(
                message=msg
            )

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
            parsed_msg = self.validate_json(msg)
            data = parsed_msg["data"]

            if msg.event == "create" or msg.event == "update":
                self._handle_create_update_event(data)
            if msg.event == "delete":
                self._handle_delete_event(data)
        except Exception:
            raise ValueError("Cannot process the message")


    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
