import os
from pathlib import Path
from typing import Any, Dict

import yaml
from pycti import get_config_variable

from .constants import ConfigKeys


class ConfigConnector:
    """Handles connector configuration loading and validation."""

    def __init__(self):
        """Initialize the connector with necessary configurations."""
        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> Dict[str, Any]:
        """
        Load the configuration from the YAML file.

        Returns:
            Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")

        if os.path.isfile(config_file_path):
            with open(config_file_path, "r", encoding="utf-8") as config_file:
                config = yaml.load(config_file, Loader=yaml.FullLoader)
        else:
            config = {}

        return config

    def _initialize_configurations(self) -> None:
        """Initialize connector configuration variables."""
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            ConfigKeys.DURATION_PERIOD,
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            ConfigKeys.API_BASE_URL,
            ["connector_hunt_io", "api_base_url"],
            self.load,
        )

        self.api_key = get_config_variable(
            ConfigKeys.API_KEY,
            ["connector_hunt_io", "api_key"],
            self.load,
        )

    def validate(self) -> None:
        """Validate that required configuration is present."""
        if not self.api_base_url:
            raise ValueError("API base URL is required")
        if not self.api_key:
            raise ValueError("API key is required")
        if not self.duration_period:
            raise ValueError("Duration period is required")
