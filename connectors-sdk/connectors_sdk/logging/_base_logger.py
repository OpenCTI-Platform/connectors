"""Base logger using the same format as pycti's logger."""

from __future__ import annotations

import logging
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar, Literal, Self

from pycti.utils.opencti_logger import CustomJsonFormatter

LOG_LEVELS = {
    "DEBUG",
    "INFO",
    "WARN",
    "WARNING",
    "ERROR",
}


def _json_formatter() -> CustomJsonFormatter:
    """Get a new instance of the CustomJsonFormatter.
    The format is the same as the one used in pycti's `AppLogger`, in order to maintain consistency.
    """
    return CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")


def _prepare_meta(meta: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Prepare metadata for logging.
    The format is the same as the one used in pycti's `AppLogger`, in order to maintain consistency.

    Args:
        meta: Optional metadata dict.
    """
    return None if meta is None else {"attributes": meta}


class BaseLogger(ABC):
    """Base class to set up a logger with a default `StreamHandler` using stderr and pycti's `AppLogger` formatter.
    Its log level is determined by connector's configuration, with the following precedence:
        1. `CONNECTOR_LOG_LEVEL` environment variable
        2. `connector.log_level` field in `config.yml`
        3. `CONNECTOR_LOG_LEVEL` field in `.env` file
        4. Default to `"ERROR"` if none of the above is found or if the value is invalid.

    Notes:
        - This class reproduces the same API as pycti's `AppLogger`, as this last is not importable from pycti.
        Once pycti's `AppLogger` will be made public and available for import, this class should be refactored
        to inherit from pycti's `AppLogger` instead of maintaining its own implementation.
    """

    _handlers: ClassVar[list[logging.Handler]] = []
    _log_level: ClassVar[Literal["DEBUG", "INFO", "WARN", "WARNING", "ERROR"]] = "ERROR"

    @classmethod
    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Setup default logging settings:
        - add a default `StreamHandler` to stderr with pycti's JSON formatter.
        - set log level according to the connector's configuration.
        This method ensures that all subclasses share the same default handlers and log level.
        """
        super().__init_subclass__(**kwargs)

        stderr_handler = logging.StreamHandler()
        stderr_handler.set_name("default_stderr_handler")
        stderr_handler.setFormatter(_json_formatter())  # pycti's formatter
        cls._handlers = [stderr_handler]

        connector_log_level = cls._get_connector_log_level()
        if connector_log_level:
            cls._log_level = connector_log_level

    @abstractmethod
    def __init__(self, name: str) -> None:
        """Instantiate a logger with the given name.
        The logger will be set up with the default handlers and log level defined in the class.

        Args:
            name: The name of the logger, which will appear in the log output.

        Notes:
            - This method is abstract and should be called via `super().__init__(name)` in subclasses.
            - The logger is set up at the `BaseLogger` level, so all subclasses share the same default handlers and log level.
            - Subclasses can implement additional logic and/or handlers in their `__init__` method,
            but they should not set up `_logger` themselves.
        """
        self._logger = logging.getLogger(name)
        self._logger.propagate = False

        for handler in self._handlers:
            self._logger.addHandler(handler)

        self._logger.setLevel(self._log_level)

    @staticmethod
    def _get_connector_main_path() -> Path:
        """Locate the main module of the running connector.
        This method is used to locate configuration files relative to connector's entrypoint.

        Notes:
            - This method assumes that the connector is launched using a file-backed entrypoint
            (i.e., `python -m <module>` or `python <file>`).
            - At module import time, `__main__.__file__` might not be available yet,
            thus this method should be called at runtime only.
        """
        main = sys.modules.get("__main__")
        if main and getattr(main, "__file__", None):
            return Path(main.__file__).resolve()  # type: ignore

        raise RuntimeError(
            "Cannot determine connector's location: __main__.__file__ is not available. "
            "Ensure the connector is launched using `python -m <module>` or a file-backed entrypoint."
        )

    @staticmethod
    def _get_log_level_from_config_yml() -> str:
        """Get connector's log level from `config.yml` file."""
        main_path = BaseLogger._get_connector_main_path()

        config_yml_path = None
        config_yml_legacy_path = main_path.parent / "config.yml"
        if config_yml_legacy_path.is_file():
            config_yml_path = config_yml_legacy_path
        else:
            config_yml_new_path = main_path.parent.parent / "config.yml"
            if config_yml_new_path.is_file():
                config_yml_path = config_yml_new_path

        if config_yml_path:
            import yaml  # type: ignore[import-untyped]

            with open(config_yml_path, "r") as f:
                config = yaml.safe_load(f)
                log_level = config.get("connector", {}).get("log_level")
                if isinstance(log_level, str):
                    return log_level.strip().upper()

        return ""  # return empty str for convenience

    @staticmethod
    def _get_log_level_from_dot_env() -> str:
        """Get connector's log level from `.env` file."""
        main_path = BaseLogger._get_connector_main_path()

        dot_env_path = main_path.parent.parent / ".env"
        if dot_env_path.is_file():
            import dotenv

            log_level = dotenv.get_key(dot_env_path, "CONNECTOR_LOG_LEVEL")
            if isinstance(log_level, str):
                return log_level.strip().upper()

        return ""  # return empty str for convenience

    @classmethod
    def _get_connector_log_level(
        cls,
    ) -> Literal["DEBUG", "INFO", "WARN", "WARNING", "ERROR"] | None:
        """Get the connector log level from environment variables, config files, or defaults.
        If the variable is not set or has an invalid value, return `None`.
        """
        log_level = os.getenv("CONNECTOR_LOG_LEVEL", "").strip().upper()
        if log_level in LOG_LEVELS:
            return log_level  # type: ignore[return-value]

        log_level = BaseLogger._get_log_level_from_config_yml()
        if log_level in LOG_LEVELS:
            return log_level  # type: ignore[return-value]

        log_level = BaseLogger._get_log_level_from_dot_env()
        if log_level in LOG_LEVELS:
            return log_level  # type: ignore[return-value]

        return None

    def get_child(self, name: str) -> Self:
        """Get a child logger of current instance, with the given name.

        Args:
            name: The name of the child logger, which will be appended to the parent logger's name.

        Returns:
            A new instance of the same logger class, with the name `<parent_name>.<name>`.
        """
        cls = self.__class__
        child_name = f"{self._logger.name}.{name}"

        return cls(name=child_name)

    def debug(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a DEBUG message.

        Args:
            message: The log message.
            meta: Optional metadata dict.
        """
        self._logger.debug(message, extra=_prepare_meta(meta))

    def info(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log an INFO message.

        Args:
            message: The log message.
            meta: Optional metadata dict.
        """
        self._logger.info(message, extra=_prepare_meta(meta))

    def warning(self, message: str, meta: dict[str, Any] | None = None) -> None:
        """Log a WARNING message.

        Args:
            message: The log message.
            meta: Optional metadata dict.
        """
        self._logger.warning(message, extra=_prepare_meta(meta))

    def error(
        self, message: str | Exception, meta: dict[str, Any] | None = None
    ) -> None:
        """Log an ERROR message.

        Args:
            message: The log message.
            meta: Optional metadata dict.
        """
        self._logger.error(message, exc_info=True, extra=_prepare_meta(meta))
