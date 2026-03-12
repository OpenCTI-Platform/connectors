"""Base logger using the same format as pycti's logger."""

import logging
from typing import Any, Literal

from pycti.utils.opencti_logger import CustomJsonFormatter


def json_formatter() -> CustomJsonFormatter:
    """Get a new instance of the CustomJsonFormatter.
    The format is the same as the one used in pycti's logger, in order to maintain consistency.
    """
    return CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")


def prepare_meta(meta: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Prepare metadata for logging.
    The format is the same as the one used in pycti's logger, in order to maintain consistency.

    Args:
        message: The log message.
        meta: Optional metadata dict.
    """
    return None if meta is None else {"attributes": meta}


class BaseLogger:
    """Base class to set up a logger with a default `StreamHandler` using stderr
    with the same JSON formatter as pycti's loggers.
    """

    def __init__(
        self,
        name: str,
        level: Literal[
            "debug",
            "info",
            "warn",
            "warning",
            "error",
            "fatal",
            "critical",
        ],
    ) -> None:
        """Set up logger with a default `StreamHandler`."""
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level.upper())
        self._logger.propagate = False

        # Add the default handler only once to avoid duplicate logs if multiple loggers are created.
        default_handler_name = f"{name}_default_handler"
        has_default_handler = any(
            handler.get_name() == default_handler_name
            for handler in self._logger.handlers
        )
        if not has_default_handler:
            console_handler = logging.StreamHandler()
            console_handler.set_name(default_handler_name)
            console_handler.setFormatter(json_formatter())
            self._logger.addHandler(console_handler)

    @classmethod
    def wrap_existing_logger(cls, existing_logger: logging.Logger) -> "BaseLogger":
        """Build a `BaseLogger` wrapper around an existing `logging.Logger` instance."""
        wrapper = cls.__new__(cls)
        wrapper._logger = existing_logger
        return wrapper

    def get_child(self, name: str) -> "BaseLogger":
        """Get a child logger of current instance, with the given name."""
        child_logger = self._logger.getChild(name)
        child_logger.propagate = True
        return BaseLogger.wrap_existing_logger(child_logger)

    def debug(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a DEBUG message.

        Args:
            message: The log message.
            meta: Optional metadata dict.
        """
        self._logger.debug(message, extra=prepare_meta(meta))

    def info(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log an INFO message.

        Args:
            message: The log message.
            meta: Optional metadata dict.
        """
        self._logger.info(message, extra=prepare_meta(meta))

    def warning(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a WARNING message.

        Args:
            message: The log message.
            meta: Optional metadata dict.
        """
        self._logger.warning(message, extra=prepare_meta(meta))

    def error(
        self, message: str | Exception, meta: dict[str, Any] | None = None
    ) -> None:
        """Log an ERROR message.

        Args:
            message: The log message.
            meta: Optional metadata dict.
        """
        self._logger.error(message, exc_info=True, extra=prepare_meta(meta))
