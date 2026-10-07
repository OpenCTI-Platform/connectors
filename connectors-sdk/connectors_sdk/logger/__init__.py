"""Logging for connectors, in the format OpenCTI expects.

Use `get_logger()` to get a logger, and log with it as with a standard Python logger.
Its logging methods also accept a `meta` dictionary for structured data:

    from connectors_sdk.logger import get_logger

    logger = get_logger(__name__)
    logger.info("Fetched indicators", meta={"count": 42})

`get_logger()` does **not** return a `logging.Logger`. It returns a
`ConnectorLoggerAdapter`, a `logging.LoggerAdapter` wrapping the standard logger of the
same name:

- Logging methods (`debug()`, `info()`, `warning()`, `error()`, `critical()`,
  `exception()`, `log()`), `isEnabledFor()`, `getEffectiveLevel()`, `setLevel()`,
  `hasHandlers()` and `name` work as on a standard logger.
- Methods that configure a logger (`addHandler()`, `addFilter()`, ...), `getChild()`
  and attributes such as `handlers` or `propagate` are not available. Use the wrapped
  logger (`logger.logger`) or `logging.getLogger(name)` for those.
- `isinstance(logger, logging.Logger)` is `False`. Type hints should use
  `ConnectorLoggerAdapter`.

No `OpenCTIConnectorHelper` is needed. Records look exactly like the ones a helper
produces, because the same pycti formatter is used.

Importing this module sets up the root logger, with the level read from the
`CONNECTOR_LOG_LEVEL` environment variable. `BaseConnectorSettings` then replaces it with
the validated `connector.log_level` value.
"""

from connectors_sdk.logger._logger import (
    ConnectorLoggerAdapter,
    configure_logging,
    get_logger,
    set_log_level,
)

__all__ = [
    "ConnectorLoggerAdapter",
    "get_logger",
    "set_log_level",
]

configure_logging()
