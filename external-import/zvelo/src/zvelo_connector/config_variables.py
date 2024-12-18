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
            env_var="CONNECTOR_DURATION_PERIOD",
            yaml_path=["connector", "duration_period"],
            config=self.load,
            required=True,
        )

        self.zvelo_client_id = get_config_variable(
            env_var="ZVELO_CLIENT_ID",
            yaml_path=["zvelo", "client_id"],
            config=self.load,
            required=True,
        )

        self.zvelo_client_secret = get_config_variable(
            env_var="ZVELO_CLIENT_SECRET",
            yaml_path=["zvelo", "client_secret"],
            config=self.load,
            required=True,
        )

        zvelo_collections = get_config_variable(
            env_var="ZVELO_COLLECTIONS",
            yaml_path=["zvelo", "collections"],
            config=self.load,
            required=True,
            default="phish,malicious,threat",
        )
        self.zvelo_collections = [x.strip() for x in zvelo_collections.split(",")]
