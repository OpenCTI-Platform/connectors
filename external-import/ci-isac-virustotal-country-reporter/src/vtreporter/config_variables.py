import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.api_url = get_config_variable(
            "VTREPORTER_API_URL",
            ["vtreporter", "api_url"],
            self.load,
        )
        self.api_key = get_config_variable(
            "VTREPORTER_API_KEY",
            ["vtreporter", "api_key"],
            self.load,
        )
        self.country = get_config_variable(
            "VTREPORTER_COUNTRY", 
            ["vtreporter", "country"], 
            self.load
        )

        # Report and file params
        self.threat_types = get_config_variable(
            "VTREPORTER_THREAT_TYPES", 
            ["vtreporter", "threat_types"], 
            self.load
        )
        self.confidence = get_config_variable(
            "VTREPORTER_CONFIDENCE", 
            ["vtreporter", "confidence"], 
            self.load
        )
        self.report_labels = get_config_variable(
            "VTREPORTER_REPORT_LABELS", 
            ["vtreporter", "report_labels"], 
            self.load
        )
        self.reliability = get_config_variable(
            "VTREPORTER_RELIABILITY", 
            ["vtreporter", "reliability"], 
            self.load
        )
        self.report_markings = get_config_variable(
            "VTREPORTER_REPORT_MARKINGS", 
            ["vtreporter", "report_markings"], 
            self.load
        )
        self.file_labels = get_config_variable(
            "VTREPORTER_FILE_LABELS", 
            ["vtreporter", "file_labels"], 
            self.load
        )
        self.file_markings = get_config_variable(
            "VTREPORTER_FILE_MARKINGS", 
            ["vtreporter", "file_markings"], 
            self.load
        )