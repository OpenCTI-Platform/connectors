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
        self._initialize_configuration()

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

    def _initialize_configuration(self) -> None:
        """
        Connector configuration variables
        """
        self.sekoia_url = get_config_variable(
            "SEKOIA_INTEL_URL",
            ["sekoia_intel", "url"],
            self.load,
            False,
            None,
            True,
        )
        self.sekoia_apikey = get_config_variable(
            "SEKOIA_INTEL_APIKEY",
            ["sekoia_intel", "apikey"],
            self.load,
            False,
            None,
            True,
        )
        self.sekoia_ioc_collection_uuid = get_config_variable(
            "SEKOIA_INTEL_IOC_COLLECTION_UUID",
            ["sekoia_intel", "ioc_collection_uuid"],
            self.load,
            False,
            None,
            True,
        )
