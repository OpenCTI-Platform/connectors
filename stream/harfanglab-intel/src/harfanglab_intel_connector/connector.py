import json

from pycti import OpenCTIConnectorHelper

from .api_client import HarfanglabClient
from .config_variables import ConfigConnector
from .cti_converter import CTIConverter
from .models import opencti
from .utils import get_context_former_value


class HarfanglabIntelConnector:
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
        self.api_client = HarfanglabClient(self.helper, self.config)

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
        indicator_id = None
        if data["type"] == "indicator":
            indicator_id = data["id"]
        if data["type"] == "relationship" and data["relationship_type"] == "based-on":
            indicator_id = data["source_ref"]
        if indicator_id is None:
            return None

        extended_indicator_data = self.helper.api.indicator.read(id=indicator_id)
        if extended_indicator_data:
            return opencti.Indicator(extended_indicator_data)
        else:
            return opencti.Indicator(data)

    def _handle_upsert(self, data: dict, event_context: dict = None):
        """
        Handle `create` or `update` event.
        :param data: Data streamed by OpenCTI
        :param event_context: Additional context for `update` event (optional)
        """
        indicator = self._instantiate_indicator(data)
        if indicator is None:
            return

        self.helper.connector_logger.info(
            f"{'[UPDATE]' if event_context else '[CREATE]'} Indicator",
            {"indicator_id": indicator.id},
        )

        if indicator.pattern_type == "stix":
            self._upsert_ioc_rule(indicator)
        if indicator.pattern_type == "sigma":
            self._upsert_sigma_rule(indicator, event_context)
        if indicator.pattern_type == "yara":
            self._upsert_yara_rule(indicator, event_context)

    def _upsert_ioc_rule(self, indicator: opencti.Indicator):
        """
        Convert each indicator's observable to an IOC rule and upsert it in Harfanglab.
        :param indicator: Indicator to upsert IOC rules for
        """
        for _, observable in indicator.observables:
            ioc_rule = self.stix_converter.create_ioc_rule(indicator, observable)
            existing_ioc_rule = self.api_client.get_ioc_rule(
                ioc_rule.type, ioc_rule.value
            )
            if existing_ioc_rule:
                ioc_rule.id = existing_ioc_rule.id
                self.api_client.patch_ioc_rule(ioc_rule)
            else:
                self.api_client.post_ioc_rule(ioc_rule)

    def _upsert_sigma_rule(self, indicator: opencti.Indicator, event_context: dict):
        """
        Convert indicator to a Sigma rule and upsert it in Harfanglab.
        :param indicator: Indicator to upsert Sigma rule for
        :param event_context: Additional context for `update` event (optional)
        :return:
        """
        sigma_rule = self.stix_converter.create_sigma_rule(indicator)
        sigma_rule_former_name = get_context_former_value(event_context, "name")
        existing_sigma_rule = self.api_client.get_sigma_rule(
            sigma_rule_former_name or sigma_rule.name
        )
        if existing_sigma_rule:
            sigma_rule.id = existing_sigma_rule.id
            self.api_client.patch_sigma_rule(sigma_rule)
        else:
            self.api_client.post_sigma_rule(sigma_rule)

    def _upsert_yara_rule(
        self, indicator: opencti.Indicator, event_context: dict = None
    ):
        """
        Convert indicator to a Yara file and upsert it in Harfanglab.
        :param indicator: Indicator to upsert Yara file for
        :param event_context: Additional context for `update` event (optional)
        :return:
        """
        yara_file = self.stix_converter.create_yara_file(indicator)
        yara_file_former_name = get_context_former_value(event_context, "name")
        existing_yara_file = self.api_client.get_yara_file(
            yara_file_former_name or yara_file.name
        )
        if existing_yara_file:
            yara_file.id = existing_yara_file.id
            self.api_client.patch_yara_file(yara_file)
        else:
            self.api_client.post_yara_file(yara_file)

    def _handle_delete(self, data: dict):
        """
        Handle `delete` event.
        :param data: Data streamed by OpenCTI
        """
        indicator = self._instantiate_indicator(data)
        if indicator is None:
            return

        self.helper.connector_logger.info(
            "[DELETE] Indicator", {"indicator_id": indicator.id}
        )

        if indicator.pattern_type == "stix":
            self._delete_ioc_rule(indicator)
        if indicator.pattern_type == "sigma":
            self._delete_sigma_rule(indicator)
        if indicator.pattern_type == "yara":
            self._delete_yara_file(indicator)

    def _delete_ioc_rule(self, indicator: opencti.Indicator):
        """
        Convert indicator to an IOC rule and delete it from Harfanglab.
        :param indicator: Indicator to delete IOC rule for
        """
        for _, observable in indicator.observables:
            ioc_rule = self.stix_converter.create_ioc_rule(indicator, observable)
            existing_ioc_rule = self.api_client.get_ioc_rule(
                ioc_rule.type, ioc_rule.value
            )
            if existing_ioc_rule:
                if self.config.harfanglab_remove_indicator:
                    self.api_client.delete_ioc_rule(existing_ioc_rule)
                else:
                    existing_ioc_rule.enabled = False
                    self.api_client.patch_ioc_rule(existing_ioc_rule)

    def _delete_sigma_rule(self, indicator: opencti.Indicator):
        """
        Convert indicator to a Sigma rule and delete it from Harfanglab.
        :param indicator: Indicator to delete Sigma rule for
        """
        existing_sigma_rule = self.api_client.get_sigma_rule(indicator.name)
        if existing_sigma_rule:
            if self.config.harfanglab_remove_indicator:
                self.api_client.delete_sigma_rule(existing_sigma_rule)
            else:
                existing_sigma_rule.enabled = False
                self.api_client.patch_sigma_rule(existing_sigma_rule)

    def _delete_yara_file(self, indicator: opencti.Indicator):
        """
        Convert indicator to a Yara file and delete it from Harfanglab.
        :param indicator: Indicator to delete Yara file for
        """
        existing_yara_file = self.api_client.get_yara_file(indicator.name)
        if existing_yara_file:
            if self.config.harfanglab_remove_indicator:
                self.api_client.delete_yara_file(existing_yara_file)
            else:
                existing_yara_file.enabled = False
                self.api_client.patch_yara_file(existing_yara_file)

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
            case "delete":
                self._handle_delete(data)

    def run(self):
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
