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

        # Core connector configurations

        self.name = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            self.load,
        )

        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
            default="P1D",
        )

        # Extra parameters
        self.api_url = get_config_variable(
            "TEAMT5_API_BASE_URL",
            ["teamt5", "api_base_url"],
            self.load,
        )

        self.api_key = get_config_variable(
            "TEAMT5_API_KEY",
            ["teamt5", "api_key"],
            self.load,
            required=False,
            default=None,
        )

        self.client_id = get_config_variable(
            "TEAMT5_CLIENT_ID",
            ["teamt5", "client_id"],
            self.load,
            required=False,
            default=None,
        )

        self.client_secret = get_config_variable(
            "TEAMT5_CLIENT_SECRET",
            ["teamt5", "client_secret"],
            self.load,
            required=False,
            default=None,
        )

        has_api_key = bool(self.api_key)
        has_oauth = bool(self.client_id and self.client_secret)
        if not has_api_key and not has_oauth:
            raise ValueError(
                "TeamT5 connector requires either 'api_key' OR both "
                "'client_id' and 'client_secret' to be configured."
            )

        self.tlp_level = get_config_variable(
            "TEAMT5_TLP_LEVEL",
            ["teamt5", "tlp_level"],
            self.load,
            default="clear",
        )

        first_run_timestamp = get_config_variable(
            "TEAMT5_FIRST_RUN_RETRIEVAL_TIMESTAMP",
            ["teamt5", "first_run_retrieval_timestamp"],
            self.load,
            default="0",
        )
        self.first_run_retrieval_timestamp = int(first_run_timestamp)
