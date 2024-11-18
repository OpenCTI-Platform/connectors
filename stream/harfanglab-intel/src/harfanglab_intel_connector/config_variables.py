import os
from pathlib import Path

import yaml
from pycti import get_config_variable

RULE_MATURITY_OPTIONS = ("stable", "testing")


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        self.load = self._load_config()
        self._initialize_configuration()
        self._check_configuration()

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

    def _check_configuration(self) -> None:
        """
        Run configuration additional checks not handled by get_config_variables function.
        """
        if self.harfanglab_rule_maturity not in RULE_MATURITY_OPTIONS:
            raise ValueError(
                "Incorrect value for configuration parameter 'Rule Maturity'"
            )

    def _initialize_configuration(self) -> None:
        """
        Connector configuration variables
        """
        self.harfanglab_url = get_config_variable(
            "HARFANGLAB_INTEL_URL",
            ["harfanglab_intel", "url"],
            self.load,
            False,
            None,
            True,
        )
        self.harfanglab_ssl_verify = get_config_variable(
            "HARFANGLAB_INTEL_SSL_VERIFY",
            ["harfanglab_intel", "ssl_verify"],
            self.load,
            False,
            True,
        )
        self.harfanglab_token = get_config_variable(
            "HARFANGLAB_INTEL_TOKEN",
            ["harfanglab_intel", "token"],
            self.load,
            False,
            None,
            True,
        )
        self.harfanglab_source_list_name = get_config_variable(
            "HARFANGLAB_INTEL_SOURCE_LIST_NAME",
            ["harfanglab_intel", "source_list_name"],
            self.load,
            False,
            None,
            True,
        )
        self.harfanglab_remove_indicator = get_config_variable(
            "HARFANGLAB_INTEL_REMOVE_INDICATOR",
            ["harfanglab_intel", "remove_indicator"],
            self.load,
            False,
            False,
            False,
        )
        self.harfanglab_rule_maturity = get_config_variable(
            "HARFANGLAB_INTEL_RULE_MATURITY",
            ["harfanglab_intel", "rule_maturity"],
            self.load,
            False,
            None,
            True,
        )
