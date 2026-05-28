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
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "CATALYST_BASE_URL",
            ["catalyst", "base_url"],
            self.load,
        )

        self.api_key = get_config_variable(
            "CATALYST_API_KEY",
            ["catalyst", "api_key"],
            self.load,
        )

        self.tlp_level = get_config_variable(
            "CATALYST_TLP_LEVEL",
            ["catalyst", "tlp_level"],
            self.load,
            default="white",
        )

        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            self.load,
            default=False,
        )

        self.tlp_filter = get_config_variable(
            "CATALYST_TLP_FILTER",
            ["catalyst", "tlp_filter"],
            self.load,
            default=None,
        )

        self.category_filter = get_config_variable(
            "CATALYST_CATEGORY_FILTER",
            ["catalyst", "category_filter"],
            self.load,
            default=None,
        )

        self.sync_days_back = get_config_variable(
            "CATALYST_SYNC_DAYS_BACK",
            ["catalyst", "sync_days_back"],
            self.load,
            default=7,
        )

        self.create_observables = get_config_variable(
            "CATALYST_CREATE_OBSERVABLES",
            ["catalyst", "create_observables"],
            self.load,
            default=True,
        )

        self.create_indicators = get_config_variable(
            "CATALYST_CREATE_INDICATORS",
            ["catalyst", "create_indicators"],
            self.load,
            default=False,
        )
