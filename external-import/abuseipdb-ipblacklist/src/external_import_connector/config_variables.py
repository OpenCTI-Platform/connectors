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
        Connector configuration variables
        :return: None
        """
        self.api_url = get_config_variable(
            "ABUSEIPDB_URL",
            ["abuseipdbipblacklistimport", "api_url"],
            self.load,
            default="https://api.abuseipdb.com/api/v2/blacklist",
        )
        self.api_key = get_config_variable(
            "ABUSEIPDB_API_KEY", ["abuseipdbipblacklistimport", "api_key"], self.load
        )
        self.score = get_config_variable(
            "ABUSEIPDB_SCORE", ["abuseipdbipblacklistimport", "score"], self.load, True
        )
        self.limit = get_config_variable(
            "ABUSEIPDB_LIMIT",
            ["abuseipdbipblacklistimport", "limit"],
            self.load,
            default="10000",
        )

        if self.api_key and not self.limit:
            self.limit = "500000"

        self.ipversion = get_config_variable(
            "ABUSEIPDB_LIMIT_IPVERSION",
            ["abuseipdbipblacklistimport", "ipversion"],
            self.load,
            isNumber=True,
        )

        self.except_country_list = get_config_variable(
            "ABUSEIPDB_EXCEPT_COUNTRY", ["abuseipdb", "exceptcountry"], self.load
        )

        self.only_country_list = get_config_variable(
            "ABUSEIPDB_ONLY_COUNTRY", ["abuseipdb", "onlycountry"], self.load
        )

        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
            default="PT12H",
        )
