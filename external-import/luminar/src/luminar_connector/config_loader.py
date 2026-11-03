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
        if os.path.isfile(config_file_path):
            with open(config_file_path, encoding="utf-8") as f:
                return yaml.load(f, Loader=yaml.FullLoader)
        return {}

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
            default="P1D",
        )

        # Connector extra parameters
        self.luminar_base_url = get_config_variable(
            "LUMINAR_BASE_URL",
            ["luminar", "base_url"],
            self.load,
            default=LUMINAR_BASE_URL,
        )
        self.luminar_account_id = get_config_variable(
            "LUMINAR_ACCOUNT_ID", ["luminar", "account_id"], self.load, required=True
        )
        self.luminar_client_id = get_config_variable(
            "LUMINAR_CLIENT_ID", ["luminar", "client_id"], self.load, required=True
        )
        self.luminar_client_secret = get_config_variable(
            "LUMINAR_CLIENT_SECRET",
            ["luminar", "client_secret"],
            self.load,
            required=True,
        )
        self.initial_fetch_date = get_config_variable(
            "LUMINAR_INITIAL_FETCH_DATE",
            ["luminar", "initial_fetch_date"],
            self.load,
            required=True,
        )
        self.create_observable = get_config_variable(
            "LUMINAR_CREATE_OBSERVABLE",
            ["luminar", "create_observable"],
            self.load,
            default=True,
        )
        self.mask_credentials = get_config_variable(
            "LUMINAR_MASK_CREDENTIALS",
            ["luminar", "mask_credentials"],
            self.load,
            default=False,
        )

        # get_config_variable(required=True) only rejects a key that is present
        # but empty; a key missing from both env and config.yml silently
        # returns None. Fail at startup instead of calling Luminar with "None".
        missing = [
            name
            for name, value in (
                ("LUMINAR_ACCOUNT_ID", self.luminar_account_id),
                ("LUMINAR_CLIENT_ID", self.luminar_client_id),
                ("LUMINAR_CLIENT_SECRET", self.luminar_client_secret),
                ("LUMINAR_INITIAL_FETCH_DATE", self.initial_fetch_date),
            )
            if value is None or (isinstance(value, str) and not value.strip())
        ]
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
