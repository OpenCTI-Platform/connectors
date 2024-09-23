import json

from pycti import OpenCTIConnectorHelper

from .config_variables import ConfigConnector
from .api_handler import TaniumApiHandler
from .intel_cache import IntelCache
from .intel_manager import IntelManager
from .utils import is_indicator, is_observable, is_file


class TaniumStreamConnector:
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

        self._check_stream_id()

        self.tanium_api_handler = TaniumApiHandler(self.helper, self.config)
        self.intel_cache = IntelCache(self.helper)
        self.intel_manager = IntelManager(
            self.helper, self.tanium_api_handler, self.intel_cache
        )

    def _check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        no_livestream_id = (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        )
        if no_livestream_id:
            raise ValueError("Missing stream ID, please check your configurations.")

    def _handle_create_event(self, data):
        """
        Create on Tanium the entity created on OpenCTI.
        :param data: Entity created on OpenCTI platform.
        """
        if is_indicator(data):
            self.intel_manager.create_intel_from_indicator(data)
        if is_observable(data):
            self.intel_manager.create_intel_from_observable(data)
        if is_file(data):
            if self.config.tanium_hashes_in_reputation:
                self.intel_manager.create_reputation_from_file(data)
            if not self.config.tanium_no_hashes_in_intels:
                self.intel_manager.create_intel_from_observable(data)

    def _handle_update_event(self, data):
        """
        Update on Tanium the entity updated on OpenCTI.
        :param data: Entity updated on OpenCTI platform.
        """
        if is_indicator(data):
            self.intel_manager.update_intel_from_indicator(data)
        elif is_observable(data) or is_file(data):
            self.intel_manager.update_intel_from_observable(data)

    def _handle_delete_event(self, data):
        """
        Delete on Tanium the entity deleted on OpenCTI.
        :param data: Entity deleted on OpenCTI platform.
        """
        self.intel_manager.delete_intel(data)
        if is_file(data):
            self.intel_manager.delete_reputation(data)

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        """
        try:
            data = json.loads(msg.data)["data"]
        except:
            raise ValueError("Cannot process the message")

        handled_event = msg.event in ["create", "update", "delete"]
        handled_entity = is_indicator(data) or is_observable(data) or is_file(data)
        if not (handled_event and handled_entity):
            return

        data_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension("id", data)
        self.helper.connector_logger.info(
            f"[{msg.event.upper()}] Processing {data['type']}", {"id": data_opencti_id}
        )
        if msg.event == "create":
            self._handle_create_event(data)
        if msg.event == "update":
            self._handle_update_event(data)
        if msg.event == "delete":
            self._handle_delete_event(data)

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
