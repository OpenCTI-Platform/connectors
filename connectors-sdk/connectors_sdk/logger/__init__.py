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

No `OpenCTIConnectorHelper` is needed. `OPENCTI_JSON_LOGGING` decides who owns the
logging setup, as for pycti:

- Enabled (default): the SDK, so no setup is needed. Records are written to stderr as
  JSON, with pycti's formatter, and every other root handler is removed. Until the
  settings are parsed, the level comes from `CONNECTOR_LOG_LEVEL` (`error` when it is
  not set or invalid, with a warning record saying so).
- Disabled: the developer, who configures the handlers (e.g. with
  `logging.basicConfig()`). Once the settings are parsed, the SDK only adds Python's
  default handler (plain text) if nothing is configured.

Either way, the SDK sets the root logger's level: from `CONNECTOR_LOG_LEVEL` until the
settings are parsed, then from the settings. Unlike pycti, the level also applies when
the developer configured the handlers.

Once the connector's settings are parsed, call `configure_logging()` with their log
level and format. `BaseConnectorSettings` does it for you.

In tests, nothing is needed: the SDK's pytest plugin, loaded automatically, stops the
SDK from changing the root logger, so pytest keeps capturing the records (`caplog`).
pycti's own setup, when a test creates a real `OpenCTIConnectorHelper`, is not covered.
"""

from connectors_sdk.logger._logger import (
    ConnectorLoggerAdapter,
    configure_logging,
    get_logger,
)

__all__ = [
    "ConnectorLoggerAdapter",
    "configure_logging",
    "get_logger",
]
