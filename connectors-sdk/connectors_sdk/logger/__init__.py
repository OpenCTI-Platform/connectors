"""Logging for connectors, in the format OpenCTI expects.

Use `get_connector_logger()` to get a logger. It behaves like a standard Python logger,
and it also accepts a `meta` dictionary for structured data:

    from connectors_sdk.logger import get_connector_logger

    logger = get_connector_logger(__name__)
    logger.info("Fetched indicators", meta={"count": 42})

No `OpenCTIConnectorHelper` is needed. Records look exactly like the ones a helper
produces, because the same pycti formatter is used.

Loggers are grouped under two names, called namespaces:

- `connector`, for the loggers a connector asks for with `get_connector_logger()`;
- `connectors_sdk`, for the loggers the SDK uses itself, with `get_sdk_logger()`.

Two namespaces means the level of one can be changed without changing the other. These
two are the only loggers the SDK sets up. Loggers created with `logging.getLogger()`,
and the root logger, are left untouched.

The level is read from the environment or from the connector's configuration file when
the first record is logged. `BaseConnectorSettings` then replaces it with the validated
`connector.log_level` value.
"""

from __future__ import annotations

from connectors_sdk.logger._logger import (
    ExtendedLogger,
    configure_logger,
    get_extended_logger,
)

__all__ = [
    "ExtendedLogger",
    "get_connector_logger",
    "get_sdk_logger",
]


def get_connector_logger(name: str) -> ExtendedLogger:
    """Get a logger for a connector's own code.

    Args:
        name (str): The logger's name, usually the calling module's `__name__`.

    Returns:
        ExtendedLogger: A logger under the `connector` namespace, accepting a `meta`
            dictionary.
    """
    return _get_logger("connector", name)


def get_sdk_logger(name: str) -> ExtendedLogger:
    """Get a logger for the SDK's own code.

    The SDK logs under its own namespace, so that a connector can change the level of
    the SDK's records without changing the level of its own.

    Args:
        name (str): The logger's name, usually the calling module's `__name__`.

    Returns:
        ExtendedLogger: A logger under the `connectors_sdk` namespace, accepting a
            `meta` dictionary.
    """
    return _get_logger("connectors_sdk", name)


def _get_logger(namespace: str, suffix: str) -> ExtendedLogger:
    """Set the namespace logger up, then return a child logger named `suffix`.

    Args:
        namespace (str): The namespace the logger belongs to.
        suffix (str): The name to add after the namespace.

    Returns:
        ExtendedLogger: A logger that accepts a `meta` dictionary.
    """
    namespace_logger = configure_logger(get_extended_logger(namespace))

    return namespace_logger.getChild(suffix)
