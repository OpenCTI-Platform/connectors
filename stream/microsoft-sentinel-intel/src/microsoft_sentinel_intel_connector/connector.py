import json
from json import JSONDecodeError

from pycti import OpenCTIConnectorHelper

from .api_handler import SentinelApiHandler, SentinelApiHandlerError
from .config_variables import ConfigConnector
from .utils import is_stix_indicator


class MicrosoftSentinelIntelConnector:
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

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.api = SentinelApiHandler(self.helper, self.config)

    def _check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID, please check your configurations.")

    def _create_sentinel_indicator(self, indicator_data) -> None:
        """
        Create a Threat Intelligence Indicator on Sentinel from an OpenCTI indicator.
        :param indicator_data: OpenCTI indicator data
        """
        self.api.post_indicator(indicator_data)
        self.helper.connector_logger.info(
            "[CREATE] Indicator created",
            {"opencti_id": indicator_data["id"]},
        )

    def _update_sentinel_indicator(self, indicator_data) -> None:
        """
        Update a Threat Intelligence Indicator on Sentinel from an OpenCTI observable.
        :param indicator_data: OpenCTI observable data
        """
        self.api.post_indicator(indicator_data)
        self.helper.connector_logger.info(
            "[UPDATE] Indicator updated",
            {"opencti_id": indicator_data["id"]},
        )

    def _delete_sentinel_indicator(self, indicator_data) -> None:
        """
        Delete Threat Intelligence Indicators on Sentinel corresponding to an OpenCTI observable.
        :param indicator_data: OpenCTI observable data
        """
        self.api.delete_indicator(indicator_data["id"])
        self.helper.connector_logger.info(
            "[DELETE] Indicator deleted",
            {"opencti_id": indicator_data["id"]},
        )

    def _handle_create_event(self, data):
        """
        Handle create event by trying to create the corresponding Threat Intelligence Indicator on Sentinel.
        :param data: Streamed data (representing either an observable or an indicator)
        """
        if is_stix_indicator(data):
            self._create_sentinel_indicator(data)
        else:
            self.helper.connector_logger.info("[CREATE] Entity not supported")

    def _handle_update_event(self, data):
        """
        Handle update event by trying to update the corresponding Threat Intelligence Indicator on Sentinel.
        :param data: Streamed data (representing either an observable or an indicator)
        """
        if is_stix_indicator(data):
            self._update_sentinel_indicator(data)
        else:
            self.helper.connector_logger.info("[UPDATE] Entity not supported")

    def _handle_delete_event(self, data):
        """
        Handle delete event by trying to delete the corresponding Threat Intelligence Indicators on Sentinel.
        :param data: Streamed data (representing either an observable or an indicator)
        """

        if is_stix_indicator(data):
            self._delete_sentinel_indicator(data)
        else:
            self.helper.connector_logger.info("[DELETE] Entity not supported")

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

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: string
        """
        try:
            self._check_stream_id()

            parsed_msg = self.validate_json(msg)
            data = parsed_msg["data"]

            if msg.event == "create":
                self._handle_create_event(data)
            if msg.event == "update":
                self._handle_update_event(data)
            if msg.event == "delete":
                self._handle_delete_event(data)

        except SentinelApiHandlerError as err:
            self.helper.connector_logger.error(err.msg, err.metadata)

        except Exception as err:
            self.helper.connector_logger.error(
                "[ERROR] Failed processing data {" + str(err) + "}"
            )
            self.helper.connector_logger.error(
                "[ERROR] Message data {" + str(msg) + "}"
            )
        finally:
            return None

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
