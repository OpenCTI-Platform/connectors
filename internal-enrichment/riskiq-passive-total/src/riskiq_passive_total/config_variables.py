import os
from datetime import timedelta
from pathlib import Path

import yaml
from pycti import get_config_variable
from pydantic import TypeAdapter


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

        # Connector extra parameters
        self.riskiq_username = get_config_variable(
            "RISKIQ_USERNAME",
            ["riskiq", "username"],
            self.load,
            required=True,
        )

        # Connector extra parameters
        self.riskiq_key = get_config_variable(
            "RISKIQ_API_KEY",
            ["riskiq", "api_key"],
            self.load,
            required=True,
        )

        self.max_tlp = get_config_variable(
            "RISKIQ_MAX_TLP",
            ["riskiq", "max_tlp"],
            self.load,
            default=None,
        )

        config_last_seen_time_window = get_config_variable(
            "RISKIQ_IMPORT_LAST_SEEN_TIME_WINDOW",
            ["riskiq", "import_last_seen_time_window"],
            self.load,
            default="P30D",
        )
        self.import_last_seen_time_window = TypeAdapter(timedelta).validate_python(
            config_last_seen_time_window
        )
