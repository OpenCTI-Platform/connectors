import os

import yaml
from pycti import get_config_variable


def load_config():
    """Load YAML config file from the current directory and validate log level/type early."""
    config_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "../config.yml"
    )
    config = {}

    if os.path.isfile(config_path):
        with open(config_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file) or {}

    # Validate CONNECTOR_LOG_LEVEL
    log_level = get_config_variable(
        "CONNECTOR_LOG_LEVEL", ["connector", "log_level"], config, default="info"
    ).lower()
    valid_log_levels = ["info", "error", "debug", "warn"]
    if log_level not in valid_log_levels:
        raise ValueError(
            f"Invalid CONNECTOR_LOG_LEVEL '{log_level}'. Allowed values: {valid_log_levels}"
        )

    # Validate CONNECTOR_TYPE
    connector_type = get_config_variable(
        "CONNECTOR_TYPE", ["connector", "type"], config
    )
    valid_types = [
        "INTERNAL_ENRICHMENT",
        "EXTERNAL_IMPORT",
        "INTERNAL_IMPORT_FILE",
        "INTERNAL_EXPORT_FILE",
        "EXTERNAL_ENRICHMENT",
        "STREAM",
    ]
    if not connector_type or connector_type not in valid_types:
        raise ValueError(
            f"Invalid CONNECTOR_TYPE '{connector_type}'. Allowed values: {valid_types}"
        )

    return config


def validate_required_positive_integer(value, name):
    if value is None or str(value).strip() == "":
        raise ValueError(f"Missing required configuration: {name}")
    try:
        int_value = int(value)
        if int_value <= 0:
            raise ValueError(f"Configuration '{name}' must be a positive integer. Got: {value}")
    except ValueError as exc:
        raise ValueError(
            f"Configuration '{name}' must be a positive integer. Got: {value}"
        ) from exc
    return int_value


def validate_required_string(value, name):
    if not value:
        raise ValueError(f"Missing required configuration: {name}")
    return value


def load_connector_config(config, helper):
    try:
        # Load raw values
        api_key = get_config_variable("DOPPEL_API_KEY", ["doppel", "api_key"], config)
        polling_interval = get_config_variable(
            "POLLING_INTERVAL", ["doppel", "polling_interval"], config
        )
        max_retries = get_config_variable(
            "MAX_RETRIES", ["doppel", "max_retries"], config
        )
        retry_delay = get_config_variable(
            "RETRY_DELAY", ["doppel", "retry_delay"], config
        )
        historical_days = get_config_variable(
            "HISTORICAL_POLLING_DAYS", ["doppel", "historical_polling_days"], config
        )
        update_existing_raw = get_config_variable(
            "UPDATE_EXISTING_DATA",
            ["doppel", "update_existing_data"],
            config,
            default="false",
        )

        # Validate values
        validate_required_string(api_key, "DOPPEL_API_KEY")
        polling_interval = validate_required_positive_integer(
            polling_interval, "POLLING_INTERVAL"
        )
        max_retries = validate_required_positive_integer(max_retries, "MAX_RETRIES")
        retry_delay = validate_required_positive_integer(retry_delay, "RETRY_DELAY")
        historical_days = validate_required_positive_integer(
            historical_days, "HISTORICAL_POLLING_DAYS"
        )

        # Validate and parse boolean string
        if isinstance(update_existing_raw, str):
            update_existing_lower = update_existing_raw.strip().lower()
            if update_existing_lower not in ["true", "false"]:
                raise ValueError(
                    f"UPDATE_EXISTING_DATA must be 'true' or 'false'. Got: {update_existing_raw}"
                )
            update_existing = update_existing_lower == "true"
        else:
            update_existing = bool(update_existing_raw)

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
