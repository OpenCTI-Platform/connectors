import os
import re
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigDoppel:
    def __init__(self):
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config():
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        if os.path.isfile(config_file_path):
            with open(config_file_path, "r", encoding="utf-8") as file:
                return yaml.safe_load(file) or {}
        return {}

    @staticmethod
    def _validate_positive_int(value_str, field_name):
        try:
            value = int(value_str)
            if value <= 0:
                raise ValueError
            return value
        except Exception:
            raise ValueError(
                f"{field_name} must be a positive integer (greater than 0)"
            )

    @staticmethod
    def _validate_iso8601_duration(value, field_name):
        # Match format like PT30S, PT1M, PT1H, etc.
        pattern = re.compile(r"^P(T(\d+H)?(\d+M)?(\d+S)?)?$")
        if not pattern.match(value):
            raise ValueError(
                f"{field_name} must be a valid ISO 8601 duration format (e.g., PT30S, PT5M, PT1H)"
            )
        return value

    def _initialize_configurations(self):
        self.api_base_url = get_config_variable(
            "CONNECTOR_TEMPLATE_API_BASE_URL",
            ["connector_template", "api_base_url"],
            self.load,
        )

        self.api_key = get_config_variable(
            "CONNECTOR_TEMPLATE_API_KEY", ["connector_template", "api_key"], self.load
        )

        self.alerts_endpoint = get_config_variable(
            "DOPPEL_ALERTS_ENDPOINT", ["doppel", "alerts_endpoint"], self.load
        )

        self.historical_days = self._validate_positive_int(
            get_config_variable(
                "DOPPEL_HISTORICAL_POLLING_DAYS",
                ["doppel", "historical_polling_days"],
                self.load,
            ),
            "DOPPEL_HISTORICAL_POLLING_DAYS",
        )

        self.duration_period = self._validate_iso8601_duration(
            get_config_variable(
                "CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], self.load
            ),
            "CONNECTOR_DURATION_PERIOD",
        )

        self.max_retries = self._validate_positive_int(
            get_config_variable(
                "DOPPEL_MAX_RETRIES", ["doppel", "max_retries"], self.load
            ),
            "DOPPEL_MAX_RETRIES",
        )

        self.retry_delay = self._validate_positive_int(
            get_config_variable(
                "DOPPEL_RETRY_DELAY", ["doppel", "retry_delay"], self.load
            ),
            "DOPPEL_RETRY_DELAY",
        )

        self.tlp_level = get_config_variable(
            "CONNECTOR_TEMPLATE_TLP_LEVEL",
            ["connector_template", "tlp_level"],
            self.load,
            default="clear",
        )
