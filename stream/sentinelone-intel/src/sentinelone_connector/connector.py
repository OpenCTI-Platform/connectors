import json

from pycti import OpenCTIConnectorHelper
from sentinelone_services import SentinelOneClient

from .config_loader import ConfigConnector


class SentinelOneIntelConnector:
    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the SentinelOne Intel Connector
        with necessary configurations
        """
        self.config = config
        self.helper = helper
        self.client = SentinelOneClient(config, helper)

    def check_stream_id(self) -> None:
        """
        In case of stream_id configuration is missing, raise Value Error
        :return: None
        """
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "CHANGEME"
        ):
            self.helper.connector_logger.error(
                "[CONFIG] Missing stream ID configuration"
            )
            raise ValueError("Missing stream ID, please check your configurations.")

    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works.
        Processes incoming steam messages and filters for the creation
        of Stix Indicators and creates them in SentinelOne

        :param msg: Message event from stream containing event data
        :return: None
        """

        # Check stream_id configuration, ensuring Exception can propagate
        self.check_stream_id()

        try:
            data = json.loads(msg.data)["data"]
        except Exception as e:
            raise ValueError(f"Cannot process the message: {e}")

        # Handle the Creation of an Indicator with a stix pattern
        if data["type"] == "indicator" and data["pattern_type"] == "stix":
            if msg.event == "create":
                self.helper.connector_logger.info(
                    "[CREATE] Processing indicator",
                    {
                        "Indicator ID": self.helper.get_attribute_in_extension(
                            "id", data
                        )
                    },
                )

                if self.client.create_indicator(data):
                    self.helper.connector_logger.info(
                        "[CREATE] Successfully created Indicator in SentinelOne"
                    )

    def run(self) -> None:
        """
        Start the execution of the connector
        Anchored on the process_message method
        """
        self.helper.listen_stream(message_callback=self.process_message)
