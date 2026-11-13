import json
import logging

from pycti import OpenCTIConnectorHelper
from sentinelone_connector.settings import ConnectorSettings
from sentinelone_services import SentinelOneClient


class SentinelOneIntelConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the SentinelOne Intel Connector
        with necessary configurations
        """
        self.config = config
        self.helper = helper
        self.client = SentinelOneClient(config, helper)

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works.
        Processes incoming stream messages and filters for the creation
        or update of Stix Indicators and pushes them to SentinelOne

        :param msg: Message event from stream containing event data
        :return: None
        """
        try:
            data = json.loads(msg.data)["data"]
        except Exception as e:
            raise ValueError(f"Cannot process the message: {e}")

        # Handle the Creation or Update of an Indicator with a stix pattern.
        # An update carries the full indicator, so it is pushed again to
        # propagate changes such as a new score.
        if data["type"] == "indicator" and data["pattern_type"] == "stix":
            if msg.event in {"create", "update"}:
                if self.helper.connector_logger.local_logger.isEnabledFor(logging.INFO):
                    # `get_attribute_in_extension` can take a while to execute,
                    # so we check if the logger is enabled for INFO level first
                    indicator_id = self.helper.get_attribute_in_extension("id", data)
                    self.helper.connector_logger.info(
                        "Processing indicator",
                        {"event": msg.event, "Indicator ID": indicator_id},
                    )

                if self.client.create_indicator(data):
                    self.helper.connector_logger.info(
                        "Successfully pushed Indicator to SentinelOne",
                        {"event": msg.event},
                    )

    def run(self) -> None:
        """
        Start the execution of the connector
        Anchored on the process_message method
        """
        self.helper.listen_stream(message_callback=self.process_message)
