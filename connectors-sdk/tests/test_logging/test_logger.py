"""Tests for Logger."""

import logging

import pytest
from connectors_sdk.logging._base_logger import BaseLogger
from connectors_sdk.logging.logger import Logger


@pytest.fixture(autouse=True)
def cleanup_loggers():
    yield
    for name in list(logging.Logger.manager.loggerDict):
        if name.startswith("connector"):
            connector_logger = logging.getLogger(name)
            connector_logger.handlers.clear()
            del logging.Logger.manager.loggerDict[name]


class TestLoggerInit:
    def test_inherits_from_base_logger(self) -> None:
        """Should inherit from BaseLogger."""
        # Given/When: Logger is instantiated
        # Then: It is an instance of BaseLogger
        assert isinstance(Logger(name="test"), BaseLogger)

    def test_custom_name(self) -> None:
        """Should allow custom logger name."""
        # When: Logger is instantiated with a custom name
        connector_logger = Logger(name="my_connector")

        # Then: Name is set correctly
        assert connector_logger._logger.name == "my_connector"

    def test_default_level_is_error(self) -> None:
        """Should default log level to ERROR."""
        # When: Logger is instantiated
        connector_logger = Logger(name="test")

        # Then: Level is ERROR
        assert Logger._log_level == "ERROR"
        assert connector_logger._logger.level == logging.ERROR

    def test_custom_level(self, monkeypatch) -> None:
        """Should set log level from CONNECTOR_LOG_LEVEL env var."""
        # Given: CONNECTOR_LOG_LEVEL is set
        monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "info")

        # When: Logger subclass is instantiated
        class InfoLogger(
            Logger
        ):  # Recreate a new subclass to trigger log level reading
            pass

        info_logger = InfoLogger(name="info_logger")

        # Then: Level is INFO
        assert InfoLogger._log_level == "INFO"
        assert info_logger._logger.level == logging.INFO

    def test_console_handler_present(self) -> None:
        """Should attach a StreamHandler to the logger."""
        # When: Logger is instantiated
        connector_logger = Logger(name="test")

        # Then: At least one handler is a StreamHandler
        assert any(
            isinstance(h, logging.StreamHandler)
            for h in connector_logger._logger.handlers
        )


def test_import_connectors_sdk_should_not_configure_connector_logger() -> None:
    """Importing `connectors_sdk` should not instantiate nor configure the `connector` logger."""
    import connectors_sdk  # noqa: F401

    connector_logger = logging.getLogger("connector")
    assert connector_logger.handlers == []
    assert connector_logger.propagate is True
