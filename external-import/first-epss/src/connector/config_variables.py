"""Config Variables."""

import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    # pylint: disable=too-few-public-methods

    """Config Variables."""

    def __init__(self):
        """Initialize the connector with necessary configurations"""

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
        config = {}
        if os.path.isfile(config_file_path):
            with open(config_file_path, "r", encoding="utf-8") as file:
                config = yaml.load(file, Loader=yaml.SafeLoader)

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.connector_name = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            self.load,
        )

        self.interval_days = get_config_variable(
            "FIRST_EPSS_INTERVAL", ["first_epss", "interval"], self.load, isNumber=True
        )
        self.interval_hours = self.interval_days * 24
        self.interval_seconds = self.interval_hours * 60 * 60
        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "FIRST_EPSS_API_BASE_URL",
            ["first_epss", "api_base_url"],
            self.load,
            isNumber=False,
            default="https://epss.cyentia.com",
            required=True,
        )
