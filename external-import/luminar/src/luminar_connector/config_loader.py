"""
Config File
"""

import os
from pathlib import Path

import yaml
from pycti import get_config_variable

LUMINAR_BASE_URL = "https://www.cyberluminar.com"


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
        self.luminar_base_url = get_config_variable(
            "LUMINAR_BASE_URL",
            ["luminar", "base_url"],
            self.load,
            default=LUMINAR_BASE_URL,
        )
        self.luminar_account_id = get_config_variable(
            "LUMINAR_ACCOUNT_ID", ["luminar", "account_id"], self.load
        )
        self.luminar_client_id = get_config_variable(
            "LUMINAR_CLIENT_ID", ["luminar", "client_id"], self.load
        )
        self.luminar_client_secret = get_config_variable(
            "LUMINAR_CLIENT_SECRET", ["luminar", "client_secret"], self.load
        )
        self.initial_fetch_date = get_config_variable(
            "LUMINAR_INITIAL_FETCH_DATE",
            ["luminar", "initial_fetch_date"],
            self.load,
        )
        self.create_observable = get_config_variable(
            "LUMINAR_CREATE_OBSERVABLE",
            ["luminar", "create_observable"],
            self.load,
        )
