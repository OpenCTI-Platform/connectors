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

        # Connector extra parameters
        self.riskiq_username = get_config_variable(
            "RISKIQ_USERNAME",
            ["riskiq", "username"],
            self.load,
            False,
            "",
            True,
        )

        # Connector extra parameters
        self.riskiq_key = get_config_variable(
            "RISKIQ_KEY",
            ["riskiq", "key"],
            self.load,
            False,
            "",
            True,
        )

        self.max_tlp = get_config_variable(
            "RISKIQ_MAX_TLP",
            ["first_epss", "max_tlp"],
            self.load,
            False,
            None,
            False,
        )
