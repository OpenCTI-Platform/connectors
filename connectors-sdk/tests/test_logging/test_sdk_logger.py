"""Tests for SDKLogger singleton."""

import logging
import logging.handlers
from unittest.mock import MagicMock

import pytest
from connectors_sdk.logging.sdk_logger import (
    SDKLogger,
    _OverrideConnectorHelperLoggerFilter,
    sdk_logger,
)

_SDK_LOGGER_NAME = "connectors_sdk"
_API_LOGGER_NAME = "api"


@pytest.fixture(autouse=True)
def reset_sdk_logger():
    """Reset the SDKLogger singleton and all affected stdlib loggers between tests."""
    yield
    # Reset singleton
    SDKLogger._instance = None
    # Reset SDK logger
    sdk_lgr = logging.getLogger(_SDK_LOGGER_NAME)
    sdk_lgr.handlers.clear()
    sdk_lgr.filters.clear()
    # Reset api logger
    api_lgr = logging.getLogger(_API_LOGGER_NAME)
    api_lgr.handlers.clear()
    api_lgr.filters.clear()
    api_lgr.propagate = True
    api_lgr.parent = logging.getLogger()
    # Reset any connector_name loggers registered during tests
    for name in list(logging.Logger.manager.loggerDict):
        if name in ("fake_connector", "another_connector"):
            lgr = logging.getLogger(name)
            lgr.handlers.clear()
            lgr.filters.clear()
            lgr.propagate = True
            lgr.parent = logging.getLogger()


@pytest.fixture
def mock_helper() -> MagicMock:
    """Return a mock OpenCTIConnectorHelper."""
    helper = MagicMock()
    helper.connect_name = "fake_connector"
    helper.log_level = "debug"
    return helper


@pytest.fixture
def fresh_sdk_logger() -> SDKLogger:
    """Return a fresh SDKLogger singleton (after reset)."""
    return SDKLogger()


class TestSDKLoggerSingleton:
    def test_same_instance(self, fresh_sdk_logger: SDKLogger) -> None:
        assert SDKLogger() is fresh_sdk_logger

    def test_module_level_sdk_logger_is_instance(self) -> None:
        assert isinstance(sdk_logger, SDKLogger)

    def test_logger_name_is_connectors_sdk(self, fresh_sdk_logger: SDKLogger) -> None:
        assert fresh_sdk_logger._logger.name == _SDK_LOGGER_NAME

    def test_default_level_is_info(self, fresh_sdk_logger: SDKLogger) -> None:
        assert fresh_sdk_logger._logger.level == logging.INFO

    def test_propagate_disabled(self, fresh_sdk_logger: SDKLogger) -> None:
        assert fresh_sdk_logger._logger.propagate is False

    def test_console_handler_present(self, fresh_sdk_logger: SDKLogger) -> None:
        assert any(
            isinstance(h, logging.StreamHandler)
            for h in fresh_sdk_logger._logger.handlers
        )

    def test_not_attached_on_init(self, fresh_sdk_logger: SDKLogger) -> None:
        assert fresh_sdk_logger._connector_helper_logger_attached is False


class TestAttachConnectorHelperLogger:
    def test_log_level_synced_from_helper(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        mock_helper.log_level = "warning"
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        assert fresh_sdk_logger._logger.level == logging.WARNING

    def test_connector_helper_logger_reparented(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        connector_lgr = logging.getLogger(str(mock_helper.connect_name))
        assert connector_lgr.parent is fresh_sdk_logger._logger

    def test_connector_helper_logger_handlers_cleared(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        connector_lgr = logging.getLogger(str(mock_helper.connect_name))
        connector_lgr.addHandler(
            logging.StreamHandler()
        )  # simulate pycti's own handler
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        assert connector_lgr.handlers == []

    def test_connector_helper_logger_propagate_enabled(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        connector_lgr = logging.getLogger(str(mock_helper.connect_name))
        connector_lgr.propagate = False
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        assert connector_lgr.propagate is True

    def test_connector_helper_logger_filter_added(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        connector_lgr = logging.getLogger(str(mock_helper.connect_name))
        assert any(
            isinstance(f, _OverrideConnectorHelperLoggerFilter)
            for f in connector_lgr.filters
        )

    def test_api_logger_reparented(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        api_lgr = logging.getLogger(_API_LOGGER_NAME)
        assert api_lgr.parent is fresh_sdk_logger._logger

    def test_api_logger_handlers_cleared(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        api_lgr = logging.getLogger(_API_LOGGER_NAME)
        api_lgr.addHandler(logging.StreamHandler())
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        assert api_lgr.handlers == []

    def test_api_logger_propagate_enabled(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        api_lgr = logging.getLogger(_API_LOGGER_NAME)
        api_lgr.propagate = False
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        assert api_lgr.propagate is True

    def test_api_logger_filter_added(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        api_lgr = logging.getLogger(_API_LOGGER_NAME)
        assert any(
            isinstance(f, _OverrideConnectorHelperLoggerFilter) for f in api_lgr.filters
        )

    def test_attached_flag_set(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        assert fresh_sdk_logger._connector_helper_logger_attached is True

    def test_attach_is_idempotent(
        self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock
    ) -> None:
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)
        second_helper = MagicMock()
        second_helper.connect_name = "another_connector"
        second_helper.log_level = "error"
        fresh_sdk_logger.attach_connector_helper_logger(second_helper)
        # Level must still be from the first helper
        assert fresh_sdk_logger._logger.level == logging.DEBUG
        # Second connector logger must NOT have been reparented
        second_lgr = logging.getLogger("another_connector")
        assert second_lgr.parent is not fresh_sdk_logger._logger


class TestPostAttachPropagation:
    @pytest.fixture(autouse=True)
    def attach(self, fresh_sdk_logger: SDKLogger, mock_helper: MagicMock) -> None:
        fresh_sdk_logger.attach_connector_helper_logger(mock_helper)

    @pytest.fixture
    def capture(self, fresh_sdk_logger: SDKLogger):
        mem = logging.handlers.MemoryHandler(
            capacity=100, flushLevel=logging.CRITICAL + 1
        )
        fresh_sdk_logger._logger.addHandler(mem)
        yield mem
        fresh_sdk_logger._logger.removeHandler(mem)

    def test_connector_helper_records_reach_sdk_logger(
        self, mock_helper: MagicMock, capture: logging.handlers.MemoryHandler
    ) -> None:
        logging.getLogger(str(mock_helper.connect_name)).info("from helper")
        assert any(r.getMessage() == "from helper" for r in capture.buffer)

    def test_api_records_reach_sdk_logger(
        self, capture: logging.handlers.MemoryHandler
    ) -> None:
        logging.getLogger(_API_LOGGER_NAME).info("from api")
        assert any(r.getMessage() == "from api" for r in capture.buffer)

    def test_sdk_own_records_still_handled(
        self, fresh_sdk_logger: SDKLogger, capture: logging.handlers.MemoryHandler
    ) -> None:
        fresh_sdk_logger.info("from sdk")
        assert any(r.getMessage() == "from sdk" for r in capture.buffer)


class TestOverrideConnectorHelperLoggerFilter:
    def _make_record(self, name: str) -> logging.LogRecord:
        return logging.LogRecord(
            name=name,
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None,
        )

    def test_api_name_overridden(self) -> None:
        f = _OverrideConnectorHelperLoggerFilter()
        record = self._make_record("api")
        f.filter(record)
        assert record.name == "pycti.opencti_api_client"

    def test_other_name_overridden_to_connector_helper(self) -> None:
        f = _OverrideConnectorHelperLoggerFilter()
        record = self._make_record("fake_connector")
        f.filter(record)
        assert record.name == "pycti.opencti_connector_helper"

    def test_filter_always_returns_true(self) -> None:
        f = _OverrideConnectorHelperLoggerFilter()
        record = self._make_record("anything")
        assert f.filter(record) is True
