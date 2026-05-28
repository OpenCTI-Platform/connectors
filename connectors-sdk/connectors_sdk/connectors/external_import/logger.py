"""Connector logger module.

This module provides a logger wrapper that delegates to the OpenCTI connector helper's logger.
It allows connectors and their subcomponents (clients, converters) to use logging
without directly depending on pycti.
"""

from typing import Any

from pycti import OpenCTIConnectorHelper


class ConnectorLogger:
    """Logger wrapper that delegates to the OpenCTI connector helper's logger.

    This class provides the same interface as pycti's ``AppLogger``
    (``info``, ``debug``, ``warning``, ``error``) while decoupling connector code from pycti.

    Benefits:
        - Cleaner API: ``self.logger.info(...)`` instead of ``self.helper.connector_logger.info(...)``
        - Subcomponents (clients, converters) can receive a ``ConnectorLogger`` instead of the full helper
        - If pycti's logging interface changes, only this wrapper needs updating
        - Easier to mock in tests

    Example:
        >>> logger = ConnectorLogger(helper)
        >>> logger.info("Processing entity", {"entity_id": "abc-123"})
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """Initialize the logger from a connector helper.

        Args:
            helper: The ``OpenCTIConnectorHelper`` instance to delegate logging to.
        """
        self._logger: Any = helper.connector_logger

    def info(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log an info message.

        Args:
            message: The message to log.
            meta: Optional metadata dictionary for structured logging.
        """
        self._logger.info(message, meta)

    def debug(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a debug message.

        Args:
            message: The message to log.
            meta: Optional metadata dictionary for structured logging.
        """
        self._logger.debug(message, meta)

    def warning(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a warning message.

        Args:
            message: The message to log.
            meta: Optional metadata dictionary for structured logging.
        """
        self._logger.warning(message, meta)

    def error(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log an error message.

        Args:
            message: The message to log.
            meta: Optional metadata dictionary for structured logging.
        """
        self._logger.error(message, meta)
