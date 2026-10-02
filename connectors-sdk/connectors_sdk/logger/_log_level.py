"""Read the log level a connector asked for.

This module answers one question: *which level did the user configure?* It does not
touch any logger. Applying the level is `_logger`'s job.

The level is read here instead of through `connectors_sdk.settings`, for three reasons:

- `connectors_sdk.logger` must work before the settings are validated;
- loading the whole `pydantic-settings` stack to read one string takes about 40 times
  longer than importing this module;
- `connectors_sdk.settings` imports `connectors_sdk.logger`, so using it here would
  create a circular import.

The sources are read in the same order as in
`_SettingsLoader.settings_customise_sources`. In particular, `config.yml` and `.env` are
**mutually exclusive**: when a `config.yml` exists, the `.env` file is never read.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml
from connectors_sdk._config_paths import get_config_yml_path, get_dot_env_path
from dotenv import dotenv_values

_CONNECTOR_LOG_LEVEL_ENV_VAR = "CONNECTOR_LOG_LEVEL"
# Pycti's hardcoded default (not exposed by pycti, that's why we repeat it here)
_PYCTI_DEFAULT_LOG_LEVEL = "ERROR"


def get_log_level() -> str:
    """Read the log level from the environment, then from a configuration file.

    Returns:
        str: The level name, in upper case. pycti's default level is returned when
            nothing configures one, and when the configured value is not a level
            `logging` knows.
    """
    level = os.environ.get(_CONNECTOR_LOG_LEVEL_ENV_VAR) or _get_log_level_from_file()
    level = (level or _PYCTI_DEFAULT_LOG_LEVEL).upper()

    # This value has not been through settings validation yet, so it can be anything.
    # Reporting it is the settings loader's job, and it does so with a proper validation
    # error; logging must neither fail first nor be left unconfigured.
    if level not in logging.getLevelNamesMapping():
        return _PYCTI_DEFAULT_LOG_LEVEL

    return level


def _get_log_level_from_file() -> str | None:
    """Read the log level from the connector's configuration file.

    Returns:
        str | None: The level name, or `None` when the connector has no configuration
            file, or when that file does not set a level.
    """
    if (config_yml_path := get_config_yml_path()) is not None:
        return _get_log_level_from_config_yml(config_yml_path)

    if (dot_env_path := get_dot_env_path()) is not None:
        return _get_log_level_from_dot_env(dot_env_path)

    return None


def _get_log_level_from_config_yml(path: Path) -> str | None:
    """Read `connector.log_level` from a `config.yml` file.

    Args:
        path (Path): The path of the `config.yml` file.

    Returns:
        str | None: The level name, or `None` when it is absent or the file cannot be
            read.
    """
    try:
        config_yaml = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        # Never let a malformed or unreadable file prevent logging from starting; the
        # settings loader reports configuration problems with a proper error later on.
        return None

    if not isinstance(config_yaml, dict):
        return None
    connector_config_yaml = config_yaml.get("connector")
    if not isinstance(connector_config_yaml, dict):
        return None

    connector_log_level = connector_config_yaml.get("log_level")

    return connector_log_level if isinstance(connector_log_level, str) else None


def _get_log_level_from_dot_env(path: Path) -> str | None:
    """Read `CONNECTOR_LOG_LEVEL` from a `.env` file.

    Args:
        path (Path): The path of the `.env` file.

    Returns:
        str | None: The level name, or `None` when it is absent.
    """
    # `dotenv_values` reports unreadable files through a warning and an empty result
    # rather than an exception, so there is nothing to guard against here.
    return dotenv_values(path).get(_CONNECTOR_LOG_LEVEL_ENV_VAR)
