import os
from pathlib import Path

import pytz
from dateutil.parser import parse

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
        Connector configuration variables.
        Some common env vars are already managed by pycti such as opencti's url, connector's name, duration_period...
        :return: None
        """
        # Initialize the Tanium API Handler
        self.tanium_url = get_config_variable(
            "TANIUM_INSIGHTS_URL", ["tanium_insights", "url"], self.load
        )
        self.tanium_url_console = get_config_variable(
            "TANIUM_INSIGHTS_URL_CONSOLE", ["tanium_insights", "url_console"], self.load
        )
        self.tanium_ssl_verify = get_config_variable(
            "TANIUM_INSIGHTS_SSL_VERIFY",
            ["tanium_insights", "ssl_verify"],
            self.load,
            False,
            True,
        )
        self.tanium_token = get_config_variable(
            "TANIUM_INSIGHTS_TOKEN", ["tanium_insights", "token"], self.load
        )
        self.tanium_import_alerts = get_config_variable(
            "TANIUM_INSIGHTS_IMPORT_ALERTS",
            ["tanium_insights", "import_alerts"],
            self.load,
            False,
            True,
        )
        tanium_import_start_date_var = get_config_variable(
            "TANIUM_INSIGHTS_IMPORT_START_DATE",
            ["tanium_insights", "import_start_date"],
            self.load,
            False,
            None,
        )
        self.tanium_import_start_date = (
            parse(tanium_import_start_date_var).astimezone(pytz.UTC)
            if tanium_import_start_date_var
            else None
        )
