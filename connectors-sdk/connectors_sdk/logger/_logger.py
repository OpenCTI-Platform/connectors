"""The SDK's logger.

OpenCTI expects structured data next to a log message. pycti offers this through an
`AppLogger` wrapper. The drawback is that every class that wants to log must receive an
`OpenCTIConnectorHelper`, even when it has no other use for it.

This module offers the same behaviour on top of a standard logger instead, so no helper
is needed:

    logger.info("Fetched indicators", meta={"count": 42})

`OPENCTI_JSON_LOGGING` decides who owns the logging setup, as for pycti:

- Enabled (default): the SDK. It replaces every root handler with its JSON handler. The
  logger works out of the box: if the settings are not parsed yet, the first record
  configures logging from the environment variables (see
  `_configure_logging_from_env()`).
- Disabled: the developer. Once the settings are parsed, the SDK only adds Python's
  default handler if nothing is configured.

Whoever owns the handlers, the SDK sets the root logger's level: first from
`CONNECTOR_LOG_LEVEL`, then from the settings. Once the connector's settings are parsed,
`configure_logging()` applies their log level and format. Importing the module does not
change the logging setup.

In tests, the SDK's pytest plugin (`_connectors_sdk_plugins.pytest_plugin`) replaces
`_set_sdk_json_handler()` and `_set_root_level()`, so that pytest keeps the root logger.
"""

from __future__ import annotations

import logging
import os
from collections.abc import MutableMapping
from typing import Any

from pycti.utils.opencti_logger import CustomJsonFormatter

_JSON_LOGGING_ENV_VAR = "OPENCTI_JSON_LOGGING"
_LOG_LEVEL_ENV_VAR = "CONNECTOR_LOG_LEVEL"

# Same default as `connector.log_level` in `connectors_sdk.settings` (and pycti)
_DEFAULT_LOG_LEVEL = "ERROR"

# Pycti's hardcoded format (not exposed by pycti, that's why we repeat it here)
_PYCTI_LOG_RECORD_FORMAT = "%(timestamp)s %(level)s %(name)s %(message)s"
# The values that disable JSON logging. They are the ones pydantic reads as `False`,
# so the settings (`opencti.json_logging`) read the variable the same way.
_FALSE_VALUES = ("0", "off", "f", "false", "n", "no")

# A logger used only to log the warning of `_configure_logging_from_env()`. It's a
# standard `logging.Logger`, so logging with it doesn't call that function again.
_setup_logger = logging.getLogger(__name__)
# Whether the SDK already configured logging, from the environment variables or from
# the settings. If so, the first record has nothing to do.
_logging_configured = False
# The JSON handler the SDK added to the root logger, if any
_sdk_json_handler: logging.Handler | None = None


class ConnectorLoggerAdapter(logging.LoggerAdapter[logging.Logger]):
    """A `logging.LoggerAdapter` whose logging methods also accept a `meta` dictionary.

    `meta` is stored in the record's `attributes` field, as pycti's `AppLogger` does.
    Every other argument is passed to the wrapped `logging.Logger` unchanged.

    This is **not** a `logging.Logger` (`isinstance(logger, logging.Logger)` is `False`).
    It only offers what `logging.LoggerAdapter` offers: the logging methods,
    `isEnabledFor()`, `getEffectiveLevel()`, `setLevel()`, `hasHandlers()` and `name`.
    There is no `getChild()`, no handler or filter methods, and no `handlers` or
    `propagate` attributes: use the wrapped logger, available as `self.logger`.
    """

    def isEnabledFor(self, level: int) -> bool:  # noqa: N802 (overrides `logging`)
        """Configure logging if the SDK did not yet, then tell whether `level` is enabled.

        Every logging method calls this first (see `logging.LoggerAdapter.log()`), so
        the first record configures logging, whatever the method.

        Args:
            level (int): A logging level, e.g. `logging.INFO`.

        Returns:
            bool: Whether a record at `level` would be processed.
        """
        if not _logging_configured:
            _configure_logging_from_env()
        return super().isEnabledFor(level)

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> tuple[Any, MutableMapping[str, Any]]:
        """Move `meta` into the record's `attributes` field.

        Args:
            msg (Any): The message to log.
            kwargs (MutableMapping[str, Any]): The keyword arguments of the logging call.

        Returns:
            tuple[Any, MutableMapping[str, Any]]: The message and the keyword arguments
                to pass to the wrapped logger.
        """
        meta = kwargs.pop("meta", None)
        if meta is not None:
            kwargs["extra"] = {**(kwargs.get("extra") or {}), "attributes": meta}
        return msg, kwargs


def get_logger(name: str) -> ConnectorLoggerAdapter:
    """Get an adapter around the logger named `name`, accepting a `meta` dictionary.

    The returned object is **not** a `logging.Logger`: see `ConnectorLoggerAdapter` for
    what it supports. To configure the underlying logger, use `logging.getLogger(name)`.

    Args:
        name (str): The logger's name, usually the calling module's `__name__`.

    Returns:
        ConnectorLoggerAdapter: An adapter around `logging.getLogger(name)`.
    """
    return ConnectorLoggerAdapter(logging.getLogger(name))


def configure_logging(log_level: str, json_logging: bool = True) -> None:
    """Set up the root logger with the settings' level and format, as pycti does.

    Call it as soon as the connector's settings are parsed. After this call, the first
    record no longer configures logging from the environment variables.

    - `json_logging=True`: the SDK owns the logging setup. Every root handler is
      replaced with a JSON handler.
    - `json_logging=False`: the developer owns the logging setup. The SDK removes the
      JSON handler that the first record may have added (from the environment
      variables). Then it calls `logging.basicConfig()`, which adds Python's default
      handler only if logging is not configured yet.

    In both cases, the level applies to the root logger. Unlike pycti, it also applies
    when the developer configured the handlers.

    Args:
        log_level (str): A level name, in any case (e.g. `"info"`).
        json_logging (bool): Whether the SDK owns the logging setup and writes records
            as JSON, or leaves the logging setup to the developer.

    Raises:
        ValueError: If `log_level` is not a known level name.
    """
    level = log_level.strip().upper()
    if level not in logging.getLevelNamesMapping():
        raise ValueError(f"Unknown log level: {log_level}")

    if json_logging:
        _set_sdk_json_handler()
    else:
        # Undo the JSON setup made by the first record, if any (e.g. JSON logging is
        # only disabled in `config.yml`)
        _remove_sdk_json_handler()
        logging.basicConfig()
    # Whoever owns the handlers, the connector's log level applies
    _set_root_level(level)

    global _logging_configured
    # The settings win over the environment variables: the first record must not
    # configure logging after this
    _logging_configured = True


def _configure_logging_from_env() -> None:
    """Configure logging from the environment variables, before the settings are parsed.

    The first record calls it, unless `configure_logging()` was called before. With JSON
    logging enabled, the SDK owns the logging setup: every root handler is replaced with
    a JSON handler. With JSON logging disabled, the developer owns the handlers, so they
    don't change. In both cases, the root logger's level comes from
    `CONNECTOR_LOG_LEVEL`.
    """
    env_json_logging = os.environ.get(_JSON_LOGGING_ENV_VAR, "")
    json_logging = env_json_logging.strip().lower()
    if json_logging not in _FALSE_VALUES:
        _set_sdk_json_handler()

    env_level = os.environ.get(_LOG_LEVEL_ENV_VAR)
    level = (env_level or "").strip().upper()
    if level not in logging.getLevelNamesMapping():
        # The current root level (e.g. ERROR) must not hide this warning
        _set_root_level("WARNING")
        _setup_logger.warning(
            f"Missing or invalid {_LOG_LEVEL_ENV_VAR}: the default log level applies "
            "until the settings are parsed",
            extra={
                "attributes": {
                    _LOG_LEVEL_ENV_VAR: env_level,
                    "applied_log_level": _DEFAULT_LOG_LEVEL.lower(),
                }
            },
        )
        level = _DEFAULT_LOG_LEVEL
    _set_root_level(level)

    global _logging_configured
    # The environment is read only once, by the first record
    _logging_configured = True


def _set_sdk_json_handler() -> None:
    """Replace every root handler with a JSON handler."""
    global _sdk_json_handler
    _sdk_json_handler = logging.StreamHandler()
    _sdk_json_handler.setFormatter(CustomJsonFormatter(_PYCTI_LOG_RECORD_FORMAT))

    logging.basicConfig(handlers=[_sdk_json_handler], force=True)


def _set_root_level(level: str) -> None:
    """Set the root logger's level.

    Args:
        level (str): A level name, in upper case (e.g. `"INFO"`).
    """
    logging.getLogger().setLevel(level)


def _remove_sdk_json_handler() -> None:
    """Remove the JSON handler the SDK added to the root logger, if any.

    The developer's own handlers stay, even when they write JSON records.
    """
    if _sdk_json_handler is not None:
        logging.getLogger().removeHandler(_sdk_json_handler)
