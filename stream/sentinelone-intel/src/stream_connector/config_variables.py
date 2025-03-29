import os
from pathlib import Path

import yaml
from pycti import get_config_variable

from .custom_exceptions import ConnectorConfigurationError


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
        Extra configuration variables required for the connector
        to run.

        ALL S1 info is required and thus existence checks can
        halt execution. As well as this, the url, apitoken and
        the defined amount of attempts for an api call receive
        formatting in case of user input error.

        """

        # Ensure the presence of 'APIToken ' regardless of user config.
        configured_api_key = get_config_variable(
            "SENTINELONE_INTEL_API_KEY", ["sentinelone_intel", "api_key"], self.load
        )
        if not configured_api_key:
            raise ConnectorConfigurationError("S1_API_KEY is not configured")
        self.s1_api_key = (
            configured_api_key
            if "APIToken " in configured_api_key
            else f"APIToken {configured_api_key}"
        )

        configured_account_id = get_config_variable(
            "SENTINELONE_INTEL_ACCOUNT_ID",
            ["sentinelone_intel", "account_id"],
            self.load,
        )
        if not configured_account_id:
            raise ConnectorConfigurationError("S1_ACCOUNT_ID is not configured")
        self.s1_account_id = configured_account_id

        # Ensure no slash at the end of the URL
        configured_url = get_config_variable(
            "SENTINELONE_INTEL_URL", ["sentinelone_intel", "url"], self.load
        )
        if not configured_url:
            raise ConnectorConfigurationError("S1_URL is not configured")
        self.s1_url = configured_url.rstrip("/")

        # Ensure the maximum number of API attempts is a non-zero positive integer and default to 3 if not.
        configured_api_attempts = get_config_variable(
            "SENTINELONE_INTEL_MAX_API_ATTEMPTS",
            ["sentinelone_intel", "max_api_attempts"],
            self.load,
        )
        if isinstance(configured_api_attempts, int) and configured_api_attempts > 0:
            self.max_api_attempts = configured_api_attempts
        else:
            self.max_api_attempts = 3

        self.log_s1_response = (
            get_config_variable(
                "SENTINELONE_INTEL_LOG_S1_RESPONSE",
                ["sentinelone_intel", "log_s1_response"],
                self.load,
            )
            or False
        )
