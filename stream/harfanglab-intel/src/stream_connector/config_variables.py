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

    #     # Check config parameters
    #     self.check_stream_id()
    #     if (
    #             self.config.harfanglab_remove_indicator is None
    #             or self.config.harfanglab_remove_indicator
    #             != bool(self.config.harfanglab_remove_indicator)
    #     ):
    #         raise ValueError(
    #             "Missing or incorrect value in configuration parameter 'Remove Indicator'"
    #         )
    #
    #     if (
    #             self.config.harfanglab_rule_maturity is None
    #             or self.config.harfanglab_rule_maturity not in ("stable", "testing")
    #     ):
    #         raise ValueError(
    #             "Missing or incorrect value in configuration parameter 'Rule Maturity'"
    #         )
    #
    # def check_stream_id(self) -> None:
    #     """
    #     In case of stream_id configuration is missing, raise Value Error
    #     :return: None
    #     """
    #     if (
    #             not self.helper.connect_live_stream_id
    #             or self.helper.connect_live_stream_id.lower() == "changeme"
    #     ):
    #         raise ValueError("Missing stream ID, please check your configurations.")

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
        self.harfanglab_url = get_config_variable(
            "HARFANGLAB_INTEL_URL", ["harfanglab_intel", "url"], self.load
        )

        self.harfanglab_ssl_verify = get_config_variable(
            "HARFANGLAB_INTEL_SSL_VERIFY",
            ["harfanglab_intel", "ssl_verify"],
            self.load,
            False,
            True,
        )
        self.harfanglab_token = get_config_variable(
            "HARFANGLAB_INTEL_TOKEN", ["harfanglab_intel", "token"], self.load
        )
        self.harfanglab_api_url = self.harfanglab_url + "/api/data/threat_intelligence"
        self.headers = {
            "Accept": "application/json",
            "Authorization": "Token " + self.harfanglab_token,
        }
        self.harfanglab_source_list_name = get_config_variable(
            "HARFANGLAB_INTEL_SOURCE_LIST_NAME",
            ["harfanglab_intel", "source_list_name"],
            self.load,
        )
        self.harfanglab_remove_indicator = get_config_variable(
            "HARFANGLAB_INTEL_REMOVE_INDICATOR",
            ["harfanglab_intel", "remove_indicator"],
            self.load,
        )
        self.harfanglab_rule_maturity = get_config_variable(
            "HARFANGLAB_INTEL_RULE_MATURITY",
            ["harfanglab_intel", "rule_maturity"],
            self.load,
        )
        self.harfanglab_default_markings = get_config_variable(
            "HARFANGLAB_INTEL_DEFAULT_MARKINGS",
            ["harfanglab_intel", "default_markings"],
            self.load,
        )
        self.harfanglab_source_list = {
            "name": self.harfanglab_source_list_name,
            "description": "Cyber Threat Intelligence knowledge imported from OpenCTI, and any changes must be made only to it.",
            "enabled": True,
        }
        self.harfanglab_default_score = get_config_variable(
            "HARFANGLAB_INTEL_DEFAULT_SCORE", ["harfanglab_intel", "default_score"]
        )
