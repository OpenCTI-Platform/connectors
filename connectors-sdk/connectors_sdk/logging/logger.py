"""Logger to be used within a connector."""

from typing import Literal

from connectors_sdk.logging._base_logger import BaseLogger


class ConnectorLogger(BaseLogger):
    """Logger for connectors."""

    def __init__(
        self,
        name: str = "connector",
        level: Literal[
            "debug",
            "info",
            "warn",
            "warning",
            "error",
            "fatal",
            "critical",
        ] = "info",
    ) -> None:
        """Set up logger with default handler and formatter."""
        super().__init__(name=name, level=level)


# For convenience, this module provides a default logger instance for connectors,
# but users can also create their own loggers if they need to.
logger = ConnectorLogger()
