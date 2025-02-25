from .custom_exceptions import *

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
        Extra configuration variables required for the connector
        to run. 

        ALL S1 info is required and thus existence checks can 
        halt execution. As well as this, the url, apitoken and
        the defined amount of attempts for an api call receive
        formatting in case of user input error. 

        """

        #Ensure the presence of 'APIToken ' regardless of user config.
        configured_api_key = get_config_variable("S1_API_KEY", ["SentinelOne", "api_key"], self.load)
        if not configured_api_key:
            raise ConnectorConfigurationError("S1_API_KEY is not configured")
        self.s1_api_key = configured_api_key if 'APIToken ' in configured_api_key else f"APIToken {configured_api_key}"

        configured_account_id = get_config_variable("S1_ACCOUNT_ID", ["SentinelOne", "account_id"], self.load)
        if not configured_account_id:
            raise ConnectorConfigurationError("S1_ACCOUNT_ID is not configured")
        self.s1_account_id = configured_account_id

        #Ensure no slash at the end of the URL
        configured_url = get_config_variable("S1_URL", ["SentinelOne", "url"], self.load)
        if not configured_url:
            raise ConnectorConfigurationError("S1_URL is not configured")
        self.s1_url = configured_url.rstrip('/')

        #Ensure the maximum number of API attempts is a non-zero positive integer and default to 3 if not.
        configured_api_attempts = get_config_variable("MAX_API_ATTEMPTS", ["SentinelOne", "max_api_attempts"], self.load)
        if isinstance(configured_api_attempts, int) and configured_api_attempts > 0:
            self.max_api_attempts = configured_api_attempts 
        else:
            self.max_api_attempts = 3

        configured_duration_period = get_config_variable("CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], self.load)
        if not configured_duration_period:
            raise ConnectorConfigurationError("CONNECTOR_DURATION_PERIOD is not configured")
        self.duration_period = configured_duration_period

        configured_sign = get_config_variable("SIGN", ["SentinelOne", "sign"], self.load)
        if not configured_sign:
            raise ConnectorConfigurationError("SIGN is not configured")
        self.sign = configured_sign

