"""The SDK's logger, and how logging is set up for a connector.

OpenCTI expects structured data next to a log message. pycti offers this through an
`AppLogger` wrapper. The drawback is that every class that wants to log must receive an
`OpenCTIConnectorHelper`, even when it has no other use for it.

This module offers the same behaviour on top of a standard logger instead, so no helper
is needed:

    logger.info("Fetched indicators", meta={"count": 42})

It also sets up the root logger, with the same handler and format as pycti, so that
every record of the process (SDK, connector, third-party libraries) is written once and
in the format OpenCTI expects.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import MutableMapping
from typing import Any

from pycti.utils.opencti_logger import CustomJsonFormatter

# Pycti's hardcoded format (not exposed by pycti, that's why we repeat it here)
_PYCTI_LOG_RECORD_FORMAT = "%(timestamp)s %(level)s %(name)s %(message)s"

_LOG_LEVEL_ENV_VAR = "CONNECTOR_LOG_LEVEL"
# Same default as `connector.log_level` in `connectors_sdk.settings` (and pycti)
_DEFAULT_LOG_LEVEL = "ERROR"


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

    def error(self, msg: object, *args: object, **kwargs: Any) -> None:
        """Log an error, with the traceback of the exception being handled, if any.

        pycti's `AppLogger.error` always attaches exception information. This method
        only does it when an exception is being handled, which avoids empty
        `NoneType: None` tracebacks. Pass `exc_info` explicitly to override it.

        Args:
            msg (object): The message to log.
            *args (object): The values to insert into `msg`.
            **kwargs (Any): The keyword arguments of the logging call, including `meta`.
        """
        if sys.exc_info()[0] is not None:
            kwargs.setdefault("exc_info", True)
        # This override adds a frame that `logging`'s caller detection does not skip,
        # since it lives outside `logging/__init__.py`. Without the +1, every error
        # record would report this file as its origin.
        kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 1
        super().error(msg, *args, **kwargs)


def get_logger(name: str) -> ConnectorLoggerAdapter:
    """Get an adapter around the logger named `name`, accepting a `meta` dictionary.

    The returned object is **not** a `logging.Logger`: see `ConnectorLoggerAdapter` for
    what it supports. To configure the underlying logger, use
    `logging.getLogger(name)`.

    Args:
        name (str): The logger's name, usually the calling module's `__name__`.

    Returns:
        ConnectorLoggerAdapter: An adapter around `logging.getLogger(name)`.
    """
    return ConnectorLoggerAdapter(logging.getLogger(name))


def configure_logging() -> None:
    """Add the OpenCTI JSON handler to the root logger and set its level.

    The level is read from the `CONNECTOR_LOG_LEVEL` environment variable. The
    connector's settings are not validated yet when this function is called, so a level
    set in `config.yml` or `.env` only applies once `BaseConnectorSettings` is created.

    The handler is added only when the root logger has no handler with pycti's JSON
    formatter yet, so this function is idempotent. It also prevents duplicate records:
    pycti replaces the root handlers with its own, using the same formatter, when an
    `OpenCTIConnectorHelper` is created.
    """
    root_logger = logging.getLogger()
    if not any(
        isinstance(handler.formatter, CustomJsonFormatter)
        for handler in root_logger.handlers
    ):
        handler = logging.StreamHandler()
        handler.setFormatter(CustomJsonFormatter(_PYCTI_LOG_RECORD_FORMAT))
        root_logger.addHandler(handler)

    set_log_level(os.environ.get(_LOG_LEVEL_ENV_VAR) or _DEFAULT_LOG_LEVEL)


def set_log_level(level: str) -> None:
    """Set the level of the root logger.

    Args:
        level (str): A level name, in any case (e.g. `"info"`). pycti's default level is
            used when `logging` does not know it.
    """
    level_name = level.upper()
    # The environment variable has not been through settings validation, so it can be
    # anything. Reporting it is the settings' job; logging must not fail first.
    if level_name not in logging.getLevelNamesMapping():
        level_name = _DEFAULT_LOG_LEVEL

    logging.getLogger().setLevel(level_name)
