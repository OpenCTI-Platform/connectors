# src/utils/common.py

import os

import yaml
from pycti import get_config_variable


def load_config():
    """Load YAML config file from the current directory."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../config.yml")
    if os.path.isfile(config_path):
        with open(config_path, "r") as file:
            return yaml.safe_load(file)
    return {}


def load_connector_config(config):
    return {
        "API_KEY": get_config_variable("DOPPEL_API_KEY", ["doppel", "api_key"], config),
        "POLLING_INTERVAL": get_config_variable("POLLING_INTERVAL", ["doppel", "polling_interval"], config, isNumber=True),
        "MAX_RETRIES": get_config_variable("MAX_RETRIES", ["doppel", "max_retries"], config, isNumber=True),
        "RETRY_DELAY": get_config_variable("RETRY_DELAY", ["doppel", "retry_delay"], config, isNumber=True),
        "HISTORICAL_POLLING_DAYS": get_config_variable("HISTORICAL_POLLING_DAYS", ["doppel", "historical_polling_days"], config, isNumber=True),
        "UPDATE_EXISTING_DATA": (
            get_config_variable("UPDATE_EXISTING_DATA", ["doppel", "update_existing_data"], config, default="false")
            .lower() == "true"
            if isinstance(get_config_variable("UPDATE_EXISTING_DATA", ["doppel", "update_existing_data"], config, default="false"), str)
            else bool(get_config_variable("UPDATE_EXISTING_DATA", ["doppel", "update_existing_data"], config, default="false"))
        ),
    }
