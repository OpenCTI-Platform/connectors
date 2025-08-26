import json

from pycti import OpenCTIConnectorHelper
from sentinelone_services import SentinelOneClient

from .config_loader import ConfigConnector

#TODO: REMOVE
from datetime import datetime
import logging
import time


class SentinelOneIntelConnector:

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the SentinelOne Intel Connector 
        with necessary configurations
        """
        self.config = config
        self.helper = helper
        self.client = SentinelOneClient(config, helper)

        #TODO: REMOVE
        self._setup_development_environment(helper)


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


    def process_message(self, msg) -> None:
        """
        Main process if connector successfully works
        :param msg: Message event from stream
        :return: None
        """
        try:
            self.check_stream_id()
            data = json.loads(msg.data)["data"]
        except Exception:
            raise ValueError("Cannot process the message")

        if data["type"] == "indicator" and data["pattern_type"] == "stix":
            if msg.event == "create":
                self.helper.connector_logger.info(f"Attempting to Creating IOC in s1")
                self.client.create_indicator(data)


    def run(self) -> None:
        """
        Start the execution of the connector
        """
        self.helper.listen_stream(message_callback=self.process_message)



    #TODO: REMOVE
    def _setup_development_environment(self, helper):
        helper.set_state({"start_from": "1-1","recover_until": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),})
        # Override the gross json logging system for more clarity
        logging.basicConfig(
            format="%(levelname)s %(asctime)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.DEBUG,
            force=True,
        )
        # Override the default log level names with our custom prefixes
        logging.addLevelName(logging.DEBUG, "[*]")
        logging.addLevelName(logging.INFO, "[+]")
        logging.addLevelName(logging.WARNING, "[?]")
        logging.addLevelName(logging.ERROR, "[!]")
        logging.addLevelName(logging.CRITICAL, "[⚠️]")

