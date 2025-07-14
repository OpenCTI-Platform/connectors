import os
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
        self.historical_days = int(
            get_config_variable(
                "DOPPEL_HISTORICAL_POLLING_DAYS",
                ["doppel", "historical_polling_days"],
                self.load,
            )
        )
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD", ["connector", "duration_period"], self.load
        )
        self.max_retries = int(
            get_config_variable(
                "DOPPEL_MAX_RETRIES", ["doppel", "max_retries"], self.load
            )
        )
        self.retry_delay = int(
            get_config_variable(
                "DOPPEL_RETRY_DELAY", ["doppel", "retry_delay"], self.load
            )
        )
        self.update_existing_data = (
            get_config_variable(
                "DOPPEL_UPDATE_EXISTING_DATA",
                ["doppel", "update_existing_data"],
                self.load,
                default="false",
            ).lower()
            == "true"
        )
        self.tlp_level = get_config_variable(
            "CONNECTOR_TEMPLATE_TLP_LEVEL",
            ["connector_template", "tlp_level"],
            self.load,
            default="clear",
        )
