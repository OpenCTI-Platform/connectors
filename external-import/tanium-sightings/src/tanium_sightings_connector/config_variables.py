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


        # Connector configuration
        self.connector_name = get_config_variable(
            "CONNECTOR_NAME",
            ["connector", "name"],
            self.load
        )
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Initialize the Tanium API Handler
        self.tanium_url = get_config_variable("TANIUM_INSIGHTS_URL", ["tanium_insights", "url"], self.load)
        self.tanium_url_console = get_config_variable(
            "TANIUM_INSIGHTS_URL_CONSOLE", ["tanium_insights", "url_console"], self.load
        )
        self.tanium_ssl_verify = get_config_variable(
            "TANIUM_INSIGHTS_SSL_VERIFY", ["tanium_insights", "ssl_verify"], self.load, False, True
        )
        self.tanium_token = get_config_variable(
            "TANIUM_INSIGHTS_TOKEN", ["tanium_insights", "token"], self.load
        )
        self.tanium_hashes_in_reputation = get_config_variable(
            "TANIUM_INSIGHTS_HASHES_IN_REPUTATION",
            ["tanium_insights", "hashes_in_reputation"],
            self.load,
            False,
            True,
        )
        self.tanium_no_hashes_in_intels = get_config_variable(
            "TANIUM_INSIGHTS_NO_HASHES_IN_INTELS",
            ["tanium_insights", "no_hashes_in_intels"],
            self.load,
            False,
            True,
        )
        self.tanium_auto_ondemand_scan = get_config_variable(
            "TANIUM_INSIGHTS_AUTO_ONDEMAND_SCAN",
            ["tanium_insights", "ondemand_scan"],
            self.load,
            False,
            True,
        )
        # Target computer group of the automatic quickscan (if enable)
        self.tanium_computer_groups = get_config_variable(
            "TANIUM_INSIGHTS_COMPUTER_GROUPS", ["tanium_insights", "computer_groups"], self.load, False, "1"
        ).split(",")
        self.tanium_import_alerts = get_config_variable(
            "TANIUM_INSIGHTS_IMPORT_ALERTS",
            ["tanium_insights", "import_alerts"],
            self.load,
            False,
            True,
        )
