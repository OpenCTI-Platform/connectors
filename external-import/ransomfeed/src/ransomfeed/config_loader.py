"""
Configuration Loader
Handles loading and validation of connector configuration
"""
import os
from pathlib import Path
import yaml
from pycti import get_config_variable


class ConfigLoader:
    """
    Loads and manages connector configuration
    """

    def __init__(self):
        """
        Initialize the configuration loader
        """
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load configuration from YAML file
        
        Returns:
            Configuration dictionary
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
        Initialize connector configuration variables
        """
        # OpenCTI connector configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # RansomFeed specific configurations
        self.api_url = get_config_variable(
            "RANSOMFEED_API_URL",
            ["ransomfeed", "api_url"],
            self.load,
        )

        self.tlp_level = get_config_variable(
            "RANSOMFEED_TLP_LEVEL",
            ["ransomfeed", "tlp_level"],
            self.load,
            default="white",
        )

        self.create_indicators = get_config_variable(
            "RANSOMFEED_CREATE_INDICATORS",
            ["ransomfeed", "create_indicators"],
            self.load,
            default=True,
        )

