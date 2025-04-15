import os

import yaml
from pycti import get_config_variable  # type: ignore

from .common import convert_hours_to_seconds
from .constants import CONFIG_FILE_PATH


class ConfigCVE:
    def __init__(self):
        """
        Initialize the CVEConnector with necessary configurations
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
        config = (
            yaml.load(
                open(CONFIG_FILE_PATH),
                Loader=yaml.FullLoader,
            )
            if os.path.isfile(CONFIG_FILE_PATH)
            else {}
        )
        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        """
        self.base_url = get_config_variable(
            "CVE_BASE_URL",
            ["cve", "base_url"],
            self.load,
        )

        self.api_key = get_config_variable(
            "CVE_API_KEY",
            ["cve", "api_key"],
            self.load,
        )

        self.config_interval = get_config_variable(
            "CVE_INTERVAL",
            ["cve", "interval"],
            self.load,
            isNumber=True,
        )

        self.interval = convert_hours_to_seconds(self.config_interval)

        self.max_date_range = get_config_variable(
            "CVE_MAX_DATE_RANGE", ["cve", "max_date_range"], self.load, isNumber=True
        )

        self.maintain_data = get_config_variable(
            "CVE_MAINTAIN_DATA", ["cve", "maintain_data"], self.load
        )

        self.pull_history = get_config_variable(
            "CVE_PULL_HISTORY", ["cve", "pull_history"], self.load
        )

        self.history_start_year = get_config_variable(
            "CVE_HISTORY_START_YEAR",
            ["cve", "history_start_year"],
            self.load,
            isNumber=True,
        )
