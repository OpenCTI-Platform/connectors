import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
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
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        self.x_opencti_score = get_config_variable(
            "CONNECTOR_IPSUM_DEFAULT_X_OPENCTI_SCORE",
            ["connector_ipsum", "default_x_opencti_score"],
            self.load,
            default=60,
            isNumber=True,
        )

        self.api_base_url = get_config_variable(
            "CONNECTOR_IPSUM_API_BASE_URL",
            ["connector_ipsum", "api_base_url"],
            self.load,
            default="https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/5.txt",
        )

        self.api_key = get_config_variable(
            "CONNECTOR_IPSUM_API_KEY",
            ["connector_ipsum", "api_key"],
            self.load,
            required=False,
        )
