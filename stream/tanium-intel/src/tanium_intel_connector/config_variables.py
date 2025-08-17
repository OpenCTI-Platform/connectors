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
        self.tanium_url = get_config_variable(
            "TANIUM_INTEL_URL", ["tanium_intel", "url"], self.load
        )
        self.tanium_url_console = get_config_variable(
            "TANIUM_INTEL_URL_CONSOLE", ["tanium_intel", "url_console"], self.load
        )
        self.tanium_ssl_verify = get_config_variable(
            "TANIUM_INTEL_SSL_VERIFY",
            ["tanium_intel", "ssl_verify"],
            self.load,
            False,
            True,
        )
        self.tanium_token = get_config_variable(
            "TANIUM_INTEL_TOKEN", ["tanium_intel", "token"], self.load
        )
        self.tanium_hashes_in_reputation = get_config_variable(
            "TANIUM_INTEL_HASHES_IN_REPUTATION",
            ["tanium_intel", "hashes_in_reputation"],
            self.load,
            False,
            True,
        )
        self.tanium_no_hashes_in_intels = get_config_variable(
            "TANIUM_INTEL_NO_HASHES_IN_INTELS",
            ["tanium_intel", "no_hashes_in_intels"],
            self.load,
            False,
            True,
        )
        self.tanium_auto_ondemand_scan = get_config_variable(
            "TANIUM_INTEL_AUTO_ONDEMAND_SCAN",
            ["tanium_intel", "auto_ondemand_scan"],
            self.load,
            False,
            True,
        )
        # Target computer group of the automatic quickscan (if enable)
        tanium_computer_groups_var = get_config_variable(
            "TANIUM_INTEL_COMPUTER_GROUPS",
            ["tanium_intel", "computer_groups"],
            self.load,
            False,
            "1",
        )
        self.tanium_computer_groups = tanium_computer_groups_var.split(",")
