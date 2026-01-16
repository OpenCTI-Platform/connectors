from typing import Any, Protocol


class LoggerProtocol(Protocol):
    """Protocol for OpenCTIApiClient logger class."""

    def debug(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a debug message.

        :param message: Message to log
        :type message: str
        :param meta: Optional metadata to include
        :type meta: dict or None
        """

    def info(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log an info message.

        :param message: Message to log
        :type message: str
        :param meta: Optional metadata to include
        :type meta: dict or None
        """

    def warning(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a warning message.

        :param message: Message to log
        :type message: str
        :param meta: Optional metadata to include
        :type meta: dict or None
        """

    def error(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log an error message.

        :param message: Message to log
        :type message: str
        :param meta: Optional metadata to include
        :type meta: dict or None
        """
