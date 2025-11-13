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

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "FIRST_EPSS_API_BASE_URL",
            ["first_epss", "api_base_url"],
            self.load,
            False,
            "https://api.first.org/data/v1/epss",
            True,
        )

        self.max_tlp = get_config_variable(
            "FIRST_EPSS_MAX_TLP",
            ["first_epss", "max_tlp"],
            self.load,
            False,
            None,
            False,
        )
