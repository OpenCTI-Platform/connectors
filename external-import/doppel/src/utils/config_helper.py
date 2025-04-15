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


def validate_required_positive_integer(value, name):
    if value is None or str(value).strip() == "":
        raise ValueError(f"Missing required configuration: {name}")
    try:
        int_value = int(value)
        if int_value <= 0:
            raise ValueError()
    except ValueError:
        raise ValueError(f"Configuration '{name}' must be a positive integer. Got: {value}")
    return int_value


def validate_required_string(value, name):
    if not value:
        raise ValueError(f"Missing required configuration: {name}")
    return value


def load_connector_config(config, helper):
    try:
        # Load raw values
        api_key = get_config_variable("DOPPEL_API_KEY", ["doppel", "api_key"], config)
        polling_interval = get_config_variable("POLLING_INTERVAL", ["doppel", "polling_interval"], config)
        max_retries = get_config_variable("MAX_RETRIES", ["doppel", "max_retries"], config)
        retry_delay = get_config_variable("RETRY_DELAY", ["doppel", "retry_delay"], config)
        historical_days = get_config_variable("HISTORICAL_POLLING_DAYS", ["doppel", "historical_polling_days"], config)
        update_existing_raw = get_config_variable("UPDATE_EXISTING_DATA", ["doppel", "update_existing_data"], config, default="false")

        # Validate values
        validate_required_string(api_key, "DOPPEL_API_KEY")
        polling_interval = validate_required_positive_integer(polling_interval, "POLLING_INTERVAL")
        max_retries = validate_required_positive_integer(max_retries, "MAX_RETRIES")
        retry_delay = validate_required_positive_integer(retry_delay, "RETRY_DELAY")
        historical_days = validate_required_positive_integer(historical_days, "HISTORICAL_POLLING_DAYS")

        update_existing = (
            update_existing_raw.lower() == "true"
            if isinstance(update_existing_raw, str)
            else bool(update_existing_raw)
        )

        return {
            "API_KEY": api_key,
            "POLLING_INTERVAL": polling_interval,
            "MAX_RETRIES": max_retries,
            "RETRY_DELAY": retry_delay,
            "HISTORICAL_POLLING_DAYS": historical_days,
            "UPDATE_EXISTING_DATA": update_existing,
        }

    except ValueError as error:
        helper.log_error(f"Configuration error: {str(error)}")
        return None
