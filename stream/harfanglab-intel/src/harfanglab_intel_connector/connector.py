import json

from pycti import OpenCTIConnectorHelper

from .api_client import HarfanglabClient
from .config_variables import ConfigConnector
from .cti_converter import CTIConverter
from .models import opencti
from .utils import build_observable_query_filters


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

        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.stix_converter = CTIConverter(self.config)
        self.api_client = HarfanglabClient(self.helper, self.config)

    def _get_indicator(self, indicator_id: str) -> opencti.Indicator:
        indicator_data = self.helper.api.indicator.read(id=indicator_id)
        indicator = opencti.Indicator(indicator_data)

        indicator_observables = indicator.observables.copy()
        if indicator.pattern_type == "stix":
            observables_filters = build_observable_query_filters(indicator.pattern)
            # TODO: remove duplicates
            observables_from_pattern = self.helper.api.stix_cyber_observable.list(
                filters={
                    "mode": "or",
                    "filters": observables_filters,
                    "filterGroups": [],
                }
            )
            observables_from_pattern = [
                opencti.Observable(observable)
                for observable in observables_from_pattern
            ]
            indicator_observables.extend(observables_from_pattern)
        indicator.observables = indicator_observables
        return indicator

    def _handle_upsert(self, indicator_id: str) -> None:
        indicator = self._get_indicator(indicator_id)
        for observable in indicator.observables:
            if indicator.pattern_type == "stix":
                ioc_rule = self.stix_converter.create_ioc_rule(indicator, observable)
                existing_ioc_rule = self.api_client.get_ioc_rule(ioc_rule.value)
                if existing_ioc_rule:
                    ioc_rule.id = existing_ioc_rule.id
                    self.api_client.patch_ioc_rule(ioc_rule)
                else:
                    self.api_client.post_ioc_rule(ioc_rule)

        if indicator.pattern_type == "sigma":
            sigma_rule = self.stix_converter.create_sigma_rule(indicator)
            existing_sigma_rule = self.api_client.get_sigma_rule(sigma_rule.content)
            if existing_sigma_rule:
                sigma_rule.id = existing_sigma_rule.id
                self.api_client.patch_sigma_rule(sigma_rule)
            else:
                self.api_client.post_sigma_rule(sigma_rule)
        if indicator.pattern_type == "yara":
            yara_file = self.stix_converter.create_yara_file(indicator)
            existing_yara_file = self.api_client.get_yara_file(yara_file.content)
            if existing_yara_file:
                yara_file.id = existing_yara_file.id
                self.api_client.patch_yara_file(yara_file)
            else:
                self.api_client.post_yara_file(yara_file)

    def _handle_delete(self, indicator_id: str) -> None:
        indicator = self._get_indicator(indicator_id)
        for observable in indicator.observables:
            if indicator.pattern_type == "stix":
                ioc_rule = self.stix_converter.create_ioc_rule(indicator, observable)
                existing_ioc_rule = self.api_client.get_ioc_rule(ioc_rule.value)
                if existing_ioc_rule:
                    if self.config.harfanglab_remove_indicator:
                        self.api_client.delete_ioc_rule(existing_ioc_rule)
                    else:
                        existing_ioc_rule.enabled = False
                        self.api_client.patch_ioc_rule(existing_ioc_rule)
        if indicator.pattern_type == "sigma":
            existing_sigma_rule = self.api_client.get_sigma_rule(indicator.pattern)
            if existing_sigma_rule:
                if self.config.harfanglab_remove_indicator:
                    self.api_client.delete_sigma_rule(existing_sigma_rule)
                else:
                    existing_sigma_rule.enabled = False
                    self.api_client.patch_sigma_rule(existing_sigma_rule)
        if indicator.pattern_type == "yara":
            existing_yara_file = self.api_client.get_yara_file(indicator.pattern)
            if existing_yara_file:
                if self.config.harfanglab_remove_indicator:
                    self.api_client.delete_yara_file(existing_yara_file)
                else:
                    existing_yara_file.enabled = False
                    self.api_client.patch_yara_file(existing_yara_file)

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        The data passed in the data parameter is a dictionary with the following structure as shown in
        https://docs.opencti.io/latest/development/connectors/#additional-implementations
        :param msg: Message event from stream
        :return: string
        """
        try:
            data = json.loads(msg.data)["data"]
        except json.JSONDecodeError:
            self.helper.connector_logger.error(
                "[ERROR] Cannot parse message's data", {"msg_data": msg.data}
            )
            return

        if data["type"] == "indicator":
            match msg.event:
                case "create":
                    self.helper.connector_logger.info("[CREATE]")
                    self._handle_upsert(data["id"])
                case "update":
                    self.helper.connector_logger.info("[UPDATE]")
                    self._handle_upsert(data["id"])
                case "delete":
                    self.helper.connector_logger.info("[DELETE]")
                    self._handle_delete(data["id"])

        if data["type"] == "relationship" and data["relationship_type"] == "based-on":
            match msg.event:
                case "create":
                    self.helper.connector_logger.info("[CREATE]")
                    self._handle_upsert(data["source_ref"])
                case "update":
                    self.helper.connector_logger.info("[UPDATE]")
                    self._handle_upsert(data["source_ref"])
                case "delete":
                    self.helper.connector_logger.info("[DELETE]")
                    self._handle_delete(data["source_ref"])

    def run(self) -> None:
        """
        Run the main process in self.helper.listen() method
        The method continuously monitors messages from the platform
        The connector have the capability to listen a live stream from the platform.
        The helper provide an easy way to listen to the events.
        """
        self.helper.listen_stream(message_callback=self.process_message)
