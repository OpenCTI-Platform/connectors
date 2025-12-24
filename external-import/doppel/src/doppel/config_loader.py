import os
import re
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigDoppel:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        if os.path.isfile(config_file_path):
            with open(config_file_path, "r", encoding="utf-8") as file:
                return yaml.safe_load(file) or {}
        return {}

    @staticmethod
    def _validate_positive_int(value_str: str, field_name: str):
        """
        Check if config value is positive integer
        :return: Integer or ValueError
        """
        try:
            value = int(value_str)
            if value <= 0:
                raise ValueError
            return value
        except ValueError as e:
            raise ValueError(
                f"{field_name} must be a positive integer (greater than 0): {e}"
            ) from e

    @staticmethod
    def _validate_iso8601_duration(value: str, field_name: str):
        """
        Check format of duration_period config
        :return: duration_period value or ValueError
        """
        # Match format like PT30S, PT1M, PT1H, etc.
        pattern = re.compile(r"^P(T(\d+H)?(\d+M)?(\d+S)?)?$")
        if not pattern.match(value):
            raise ValueError(
                f"{field_name} must be a valid ISO 8601 duration format (e.g., PT30S, PT5M, PT1H)"
            )
        return value

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.duration_period = self._validate_iso8601_duration(
            get_config_variable(
                "CONNECTOR_DURATION_PERIOD",
                ["connector", "duration_period"],
                self.load,
                default="PT1H",
            ),
            "CONNECTOR_DURATION_PERIOD",
        )

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "DOPPEL_API_BASE_URL",
            ["doppel", "api_base_url"],
            self.load,
            default="https://api.doppel.com/v1",
        )

        self.api_key = get_config_variable(
            "DOPPEL_API_KEY", ["doppel", "api_key"], self.load
        )

        self.user_api_key = get_config_variable(
            "DOPPEL_USER_API_KEY", ["doppel", "user_api_key"], self.load
        )

        self.organization_code = get_config_variable(
            "DOPPEL_ORGANIZATION_CODE",
            ["doppel", "organization_code"],
            self.load,
        )

        self.alerts_endpoint = get_config_variable(
            "DOPPEL_ALERTS_ENDPOINT",
            ["doppel", "alerts_endpoint"],
            self.load,
            default="/alerts",
        )

        self.historical_days = self._validate_positive_int(
            get_config_variable(
                "DOPPEL_HISTORICAL_POLLING_DAYS",
                ["doppel", "historical_polling_days"],
                self.load,
                default=30,
            ),
            "DOPPEL_HISTORICAL_POLLING_DAYS",
        )

        self.max_retries = self._validate_positive_int(
            get_config_variable(
                "DOPPEL_MAX_RETRIES",
                ["doppel", "max_retries"],
                self.load,
                default=3,
            ),
            "DOPPEL_MAX_RETRIES",
        )

        self.retry_delay = self._validate_positive_int(
            get_config_variable(
                "DOPPEL_RETRY_DELAY",
                ["doppel", "retry_delay"],
                self.load,
                default=30,
            ),
            "DOPPEL_RETRY_DELAY",
        )

        self.tlp_level = get_config_variable(
            "DOPPEL_TLP_LEVEL",
            ["doppel", "tlp_level"],
            self.load,
            default="clear",
        )

        self.page_size = self._validate_positive_int(
            get_config_variable(
                "DOPPEL_PAGE_SIZE",
                ["doppel", "page_size"],
                self.load,
                default=100,
            ),
            "DOPPEL_PAGE_SIZE",
        )
