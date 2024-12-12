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

        self.zvelo_client_id = get_config_variable(
            "ZVELO_CLIENT_ID",
            ["zvelo", "client_id"],
            self.load,
        )

        self.zvelo_client_secret = get_config_variable(
            "ZVELO_CLIENT_SECRET",
            ["zvelo", "client_secret"],
            self.load,
        )

        self.zvelo_collections = get_config_variable(
            "ZVELO_COLLECTIONS",
            ["zvelo", "collections"],
            self.load,
        )
