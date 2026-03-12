"""SDK-wide singleton logger that captures pycti's loggers as children."""

import logging
from typing import TYPE_CHECKING

from connectors_sdk.logging._base_logger import BaseLogger

if TYPE_CHECKING:
    from pycti import OpenCTIConnectorHelper


class _OverrideConnectorHelperLoggerFilter(logging.Filter):
    """Logging filter to override the name of pycti's logger's records for consistency."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name == "api":
            record.name = "pycti.opencti_api_client"
        else:
            record.name = "pycti.opencti_connector_helper"
        return True


class SDKLogger(BaseLogger):
    """Singleton SDK logger, parent of all loggers inside the connectors-sdk and pycti's loggers.

    Logs immediately to stderr via a `StreamHandler` using pycti's `CustomJsonFormatter`.

    Once `OpenCTIConnectorHelper` is available, call `attach_connector_helper_logger`
    to reparent pycti's internal loggers under the SDK logger — all records
    emitted by pycti will then propagate up to the SDK logger automatically.

    Usage:
        # Anywhere in the connectors-sdk codebase, at any time:
        from connectors_sdk import SDKLogger
        logger = SDKLogger()
        logger.info("Works before pycti is ready")

        # Once `OpenCTIConnectorHelper` is available (e.g. in `ExternalImportConnector`):
        from connectors_sdk import attach_connector_helper_logger
        attach_connector_helper_logger(helper)

        # pycti's own internal logs now flow into the SDK logger too.
    """

    _instance: "SDKLogger | None" = None

    def __new__(cls) -> "SDKLogger":
        """Ensure only one instance of SDKLogger exists."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Set up logger with the default `StreamHandler`."""
        # Log level is set to INFO by default, but will be overridden
        # to match OpenCTIConnectorHelper's log level once it's available.
        super().__init__(name="connectors_sdk", level="info")

        self._connector_helper_logger_attached = False

    def attach_connector_helper_logger(self, helper: "OpenCTIConnectorHelper") -> None:
        """Reparent `OpenCTICConnectorHelper` and `OpenCTIApiClient` loggers under the SDK logger.
        After this call, records emitted by the helper propagate up to the SDK logger and are handled by its handlers.

        The helper's own handlers are cleared to prevent double-output.
        This is idempotent: subsequent calls are silently ignored.

        Args:
            helper: An initialized `OpenCTIConnectorHelper` instance.

        Raises:
            RuntimeError: If the SDK logger integrity check fails.
        """
        if self._connector_helper_logger_attached:
            return

        # Use the helper's log level for the SDK logger to ensure consistency in log output
        self._logger.setLevel(helper.log_level.upper())

        # Reparent `OpenCTIConnectorHelper.connector_logger`
        connector_helper_logger = logging.getLogger(str(helper.connect_name))
        connector_helper_logger.parent = self._logger
        connector_helper_logger.handlers.clear()
        connector_helper_logger.propagate = True
        connector_helper_logger.addFilter(_OverrideConnectorHelperLoggerFilter())

        # Reparent `OpenCTIApiClient.app_logger`
        connector_api_logger = logging.getLogger("api")
        connector_api_logger.parent = self._logger
        connector_api_logger.handlers.clear()
        connector_api_logger.propagate = True
        connector_api_logger.addFilter(_OverrideConnectorHelperLoggerFilter())

        self._connector_helper_logger_attached = True


# For convenience, this module provides a default logger instance,
# but `SDKLogger` can also be instantiated directly if needed (e.g. for testing purpose).
sdk_logger = SDKLogger()
