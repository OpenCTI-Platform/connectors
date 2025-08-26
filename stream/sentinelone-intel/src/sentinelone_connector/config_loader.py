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

        #SentinelOne API Basic Parameters: Mandatory.

        #Handle existence of suffix / by removing for consistency
        self.api_url = get_config_variable(
            "SENTINELONE-INTEL_API_URL",
            ["sentinelone-intel", "api_url"],
            self.load,
            default=None,  
            required=True  
        ).strip("/")


        self.api_key = get_config_variable(
            "SENTINELONE-INTEL_API_KEY",
            ["sentinelone-intel", "api_key"],
            self.load,
            default=None,  
            required=True
        )
        #Handle case of user inputted APIToken ...
        if self.api_key[0:9] == "APIToken ":
            self.api_key = self.api_key[9:]


        #SentinelOne API Filtering Parameters:

        self.account_id = get_config_variable(
            "SENTINELONE-INTEL_ACCOUNT_ID",
            ["sentinelone-intel", "account_id"],
            self.load,
            default=None,
            isNumber=True
        )

        self.site_id = get_config_variable(
            "SENTINELONE-INTEL_SITE_ID",
            ["sentinelone-intel", "site_id"],
            self.load,
            default=None,
            isNumber=True
        )

        self.group_id = get_config_variable(
            "SENTINELONE-INTEL_GROUP_ID", 
            ["sentinelone-intel", "group_id"],
            self.load,
            default=None,
            isNumber=True
        )

        #At least one of the three IDs are required to interface with the API (see README for more info)
        if (self.account_id is None and self.group_id is None and self.site_id is None):
            raise ValueError("Need to put one of acc group site, see README for more info")
        
        #API requests cannot use both an account and site ID (see README for more info)
        if (self.account_id is not None and self.site_id is not None):
            raise ValueError("Cannot use both account id and site id at same time, see README for more info")
