"""Tests for SDKLogger singleton."""

import logging

import pytest
from connectors_sdk.logging._base_logger import BaseLogger
from connectors_sdk.logging.sdk_logger import SDKLogger, sdk_logger

_SDK_LOGGER_NAME = "connectors_sdk"


@pytest.fixture(autouse=True)
def cleanup_loggers():
    """Remove any test loggers created during a test."""
    yield
    for name in list(logging.Logger.manager.loggerDict):
        if name.startswith("test_base_logger"):
            logger = logging.getLogger(name)
            logger.handlers.clear()
            del logging.Logger.manager.loggerDict[name]


@pytest.fixture
def stub_sdk_logger() -> SDKLogger:
    """Return a SDKLogger instance."""
    return SDKLogger()


class TestSDKLoggerInit:
    def test_inherits_from_base_logger(self) -> None:
        """Should inherit from BaseLogger."""
        # When/Then: SDKLogger is a BaseLogger
        assert isinstance(SDKLogger(), BaseLogger)

    def test_logger_name_must_start_with_connectors_sdk(self) -> None:
        """Should raise if logger name does not start with 'connectors_sdk'."""
        # When/Then: Instantiating with invalid name raises ValueError
        with pytest.raises(
            ValueError, match="SDKLogger name must start with 'connectors_sdk'"
        ):
            SDKLogger(name="invalid_logger_name")

    def test_logger_default_name_is_connectors_sdk(
        self, stub_sdk_logger: "SDKLogger"
    ) -> None:
        """Should default logger name to 'connectors_sdk'."""
        # When/Then: stub_sdk_logger name is correct
        assert stub_sdk_logger._logger.name == _SDK_LOGGER_NAME

    def test_default_level_is_error(self, stub_sdk_logger: "SDKLogger") -> None:
        """Should default log level to ERROR."""
        # When/Then: log level is ERROR
        assert SDKLogger._log_level == "ERROR"
        assert stub_sdk_logger._logger.level == logging.ERROR

    def test_console_handler_present(self, stub_sdk_logger: "SDKLogger") -> None:
        """Should attach a StreamHandler to the SDKLogger."""
        # When/Then: At least one handler is a StreamHandler
        assert any(
            isinstance(h, logging.StreamHandler)
            for h in stub_sdk_logger._logger.handlers
        )


class TestModuleLevelSDKLogger:
    def test_sdk_logger_is_sdk_logger_instance(self) -> None:
        """Should expose a module-level SDKLogger instance."""
        # When/Then: sdk_logger is a SDKLogger instance
        assert isinstance(sdk_logger, SDKLogger)

    def test_sdk_logger_default_name(self) -> None:
        """Should default module-level SDKLogger name to 'connectors_sdk'."""
        # When/Then: sdk_logger name is correct
        assert sdk_logger._logger.name == _SDK_LOGGER_NAME
