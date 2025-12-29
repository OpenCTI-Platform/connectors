import json

from crowdstrike_connector.settings import ConnectorSettings
from crowdstrike_services import CrowdstrikeClient, Metrics
from pycti import OpenCTIConnectorHelper


class CrowdstrikeConnector:
    """
    Crowdstrike Endpoint Security connector class
    """

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the Crowdstrike Endpoint Security Connector
        with necessary configurations
        """
        self.config = config
        self.helper = helper
        self.client = CrowdstrikeClient(helper)
        self.metrics = Metrics(
            helper.connect_name,
            config.metrics.addr,
            config.metrics.port,
        )
        self.metrics_enabled = config.metrics.enable

    def handle_logger_info(self, action: str, data: dict) -> None:
        """
        On action, update connector logger info
        :param action: Action in string
        :param data: Dict of data from stream
        :return: None
        """
        self.helper.connector_logger.info(
            f"{action} Processing indicator",
            {"Indicator ID": self.helper.get_attribute_in_extension("id", data)},
        )

    def _process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        :param msg: Message event from stream
        :return: None
        """
        try:
            if self.metrics_enabled:
                self.metrics.handle_metrics(msg)
            data = json.loads(msg.data)["data"]
        except Exception:
            raise ValueError("Cannot process the message")

        # Extract data and handle only entity type 'Indicator' from stream
        if data["type"] == "indicator" and data["pattern_type"] in ["stix"]:
            self.helper.connector_logger.info(
                "Starting to extract data...", {"pattern_type": data["pattern_type"]}
            )

            # Handle creation
            if msg.event == "create":
                self.handle_logger_info("[CREATE]", data)
                self.client.create_indicator(data, msg.event)

            # Handle update
            if msg.event == "update":
                self.handle_logger_info("[UPDATE]", data)
                self.client.update_indicator(data)

            # Handle delete
            if msg.event == "delete":
                if self.config.crowdstrike_endpoint_security.permanent_delete:
                    self.handle_logger_info("[DELETE]", data)
                    self.client.delete_indicator(data)
                else:
                    self.handle_logger_info("[DELETE ON OPENCTI ONLY]", data)
                    self.client.update_indicator(data, msg.event)

    def run(self) -> None:
        """
        Start main execution loop procedure for connector
        """
        # Start getting metrics if metrics_enabled is true
        if self.metrics_enabled:
            self.metrics.start_server()
        self.helper.listen_stream(self._process_message)
