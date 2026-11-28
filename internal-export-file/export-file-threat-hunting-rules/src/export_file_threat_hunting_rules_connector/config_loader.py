import os
from pathlib import Path

import yaml


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        if os.path.isfile(config_file_path):
            # Use a context manager (closes the handle) and safe_load to avoid
            # resource leaks and the risks of the full YAML loader.
            with open(config_file_path, encoding="utf-8") as config_file:
                config = yaml.safe_load(config_file) or {}
        else:
            config = {}
        config.setdefault("connector", {}).update({"type": "INTERNAL_EXPORT_FILE"})

        return config
