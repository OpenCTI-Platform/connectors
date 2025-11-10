import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self, helper=None):
        """
        Initialize the connector with necessary configurations
        """
        self.helper = helper
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

        # SentinelOne API Basic Parameters: Mandatory.

        # Handle existence of suffix / by removing for consistency
        self.api_url = get_config_variable(
            "SENTINELONE-INTEL_API_URL",
            ["sentinelone-intel", "api_url"],
            self.load,
            default=None,
            required=True,
        ).strip("/")

        self.api_key = get_config_variable(
            "SENTINELONE-INTEL_API_KEY",
            ["sentinelone-intel", "api_key"],
            self.load,
            default=None,
            required=True,
        )
        # Users commonly input "APIToken eyj..." or just "eyj.." as such we strip
        # "APIToken " and append it in code for consistency
        if self.api_key.startswith("APIToken "):
            self.api_key = self.api_key[9:]

        # SentinelOne API Filtering Parameters:

        self.account_id = get_config_variable(
            "SENTINELONE-INTEL_ACCOUNT_ID",
            ["sentinelone-intel", "account_id"],
            self.load,
            default=None,
        )
        if self.account_id:
            self.account_id = int(self.account_id)

        self.site_id = get_config_variable(
            "SENTINELONE-INTEL_SITE_ID",
            ["sentinelone-intel", "site_id"],
            self.load,
            default=None,
        )
        if self.site_id:
            self.site_id = int(self.site_id)

        self.group_id = get_config_variable(
            "SENTINELONE-INTEL_GROUP_ID",
            ["sentinelone-intel", "group_id"],
            self.load,
            default=None,
        )
        if self.group_id:
            self.group_id = int(self.group_id)

        # At least one of the three IDs are required to interface with the API (see README for more info)
        if self.account_id is None and self.group_id is None and self.site_id is None:
            raise ValueError(
                "[CONFIG] Missing required ID configuration: need at least one of account_id, group_id, or site_id"
            )

        # API requests cannot use both an account and site ID (see README for more info)
        if self.account_id is not None and self.site_id is not None:
            raise ValueError(
                "[CONFIG] Invalid configuration: cannot use both account_id and site_id simultaneously"
            )
