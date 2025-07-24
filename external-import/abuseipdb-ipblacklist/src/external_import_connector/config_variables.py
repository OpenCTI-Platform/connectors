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
            ["abuseipdb", "api_url"],
            self.load,
            default="https://api.abuseipdb.com/api/v2/blacklist",
        )

        self.api_key = get_config_variable(
            "ABUSEIPDB_API_KEY", ["abuseipdb", "api_key"], self.load, required=True
        )

        self.score = get_config_variable(
            "ABUSEIPDB_SCORE", ["abuseipdb", "score"], self.load, True
        )

        self.limit = get_config_variable(
            "ABUSEIPDB_LIMIT",
            ["abuseipdb", "limit"],
            self.load,
            default="500000",
        )

        self.ipversion = get_config_variable(
            "ABUSEIPDB_IPVERSION",
            ["abuseipdb", "ipversion"],
            self.load,
            default="mixed",
        )

        self.except_country_list = get_config_variable(
            "ABUSEIPDB_EXCEPT_COUNTRY", ["abuseipdb", "exceptcountry"], self.load
        )

        self.only_country_list = get_config_variable(
            "ABUSEIPDB_ONLY_COUNTRY", ["abuseipdb", "onlycountry"], self.load
        )

        self.create_indicator = bool(
            get_config_variable(
                "ABUSEIPDB_CREATE_INDICATOR",
                ["abuseipdb", "create_indicator"],
                self.load,
                default=False,
            )
        )

        self.tlp_level = get_config_variable(
            "ABUSEIPDB_TLP_LEVEL",
            ["abuseipdb", "tlp_level"],
            self.load,
            default="clear",
        )

        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
            default="PT12H",
        )
