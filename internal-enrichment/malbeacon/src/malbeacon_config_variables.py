import os

import yaml
from pycti import get_config_variable


class ConfigMalbeacon:
    def __init__(self):
        """
        Initialize the Malbeacon connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
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

        self.connector_scope = get_config_variable(
            "CONNECTOR_SCOPE",
            ["connector", "scope"],
            self.load,
        )

        self.api_key = get_config_variable(
            "MALBEACON_API_KEY", ["malbeacon", "api_key"], self.load
        )

        self.api_base_url = get_config_variable(
            "MALBEACON_API_BASE_URL", ["malbeacon", "api_base_url"], self.load
        )

        self.indicator_score_level = get_config_variable(
            "MALBEACON_INDICATOR_SCORE_LEVEL",
            ["malbeacon", "indicator_score_level"],
            self.load,
        )

        self.max_tlp = get_config_variable(
            "MALBEACON_MAX_TLP",
            ["malbeacon", "max_tlp"],
            self.load,
        )
