"""Logger of the hunt connectors.

Hunt connectors log through the OpenCTI connector helper's logger, with a
positional ``meta`` dictionary, as pycti's ``AppLogger`` does. The wrapper lives in
the hunt package so that it does not depend on the external import connector's
modules.
"""

from typing import Any


class ConnectorLogger:
    """Logger wrapper that delegates to the OpenCTI connector helper's logger.

    Example:
        >>> logger = ConnectorLogger(helper)
        >>> logger.info("Processing entity", {"entity_id": "abc-123"})
    """

    def __init__(self, helper: Any) -> None:
        """Initialize the logger from a connector helper.

        Args:
            helper: The ``OpenCTIConnectorHelper`` instance to delegate logging to.
        """
        self._logger: Any = helper.connector_logger

    def info(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log an info message."""
        self._logger.info(message, meta)

    def debug(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a debug message."""
        self._logger.debug(message, meta)

    def warning(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a warning message."""
        self._logger.warning(message, meta)

    def error(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log an error message."""
        self._logger.error(message, meta)
