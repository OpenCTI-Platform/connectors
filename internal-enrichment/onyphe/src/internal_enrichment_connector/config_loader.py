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
        self.base_url = get_config_variable(
            "ONYPHE_BASE_URL",
            ["onyphe", "base_url"],
            self.load,
            default="https://www.onyphe.io/api/v2/",
        )

        self.api_key = get_config_variable(
            "ONYPHE_API_KEY",
            ["onyphe", "api_key"],
            self.load,
        )

        self.max_tlp = get_config_variable(
            "ONYPHE_MAX_TLP",
            ["onyphe", "max_tlp"],
            self.load,
            default="TLP:AMBER",
        )

        self.time_since = get_config_variable(
            "ONYPHE_TIME_SINCE",
            ["onyphe", "time_since"],
            self.load,
            default="1w",
        )

        self.default_score = get_config_variable(
            "ONYPHE_DEFAULT_SCORE",
            ["onyphe", "default_score"],
            self.load,
            default=50,
            isNumber=True,
        )

        self.text_pivots = get_config_variable(
            "ONYPHE_TEXT_PIVOTS", ["onyphe", "text_pivots"], self.load, default=None
        )

        self.import_search_results = get_config_variable(
            "ONYPHE_IMPORT_SEARCH_RESULTS",
            ["onyphe", "import_search_results"],
            self.load,
            default=True,
        )

        self.create_note = get_config_variable(
            "ONYPHE_CREATE_NOTE",
            ["onyphe", "create_note"],
            self.load,
            default=False,
        )

        self.import_full_data = get_config_variable(
            "ONYPHE_IMPORT_FULL_DATA",
            ["onyphe", "import_full_data"],
            self.load,
            default=False,
        )

        self.auto = get_config_variable(
            "CONNECTOR_AUTO",
            ["connector", "auto"],
            self.load,
            default=False,
        )
