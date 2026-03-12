"""Tests for ConnectorLogger."""

import logging

import pytest
from connectors_sdk.logging._base_logger import BaseLogger
from connectors_sdk.logging.logger import ConnectorLogger, logger


@pytest.fixture(autouse=True)
def cleanup_loggers():
    yield
    for name in list(logging.Logger.manager.loggerDict):
        if name.startswith("connector"):
            lgr = logging.getLogger(name)
            lgr.handlers.clear()
            del logging.Logger.manager.loggerDict[name]


class TestConnectorLoggerInit:
    def test_default_name_is_connector(self) -> None:
        lgr = ConnectorLogger()
        assert lgr._logger.name == "connector"

    def test_default_level_is_info(self) -> None:
        lgr = ConnectorLogger()
        assert lgr._logger.level == logging.INFO

    def test_custom_name(self) -> None:
        lgr = ConnectorLogger(name="my_connector")
        assert lgr._logger.name == "my_connector"

    def test_custom_level(self) -> None:
        lgr = ConnectorLogger(name="connector_debug", level="debug")
        assert lgr._logger.level == logging.DEBUG

    def test_is_not_singleton(self) -> None:
        """ConnectorLogger must NOT be a singleton — each instance is independent."""
        a = ConnectorLogger(name="connector_a")
        b = ConnectorLogger(name="connector_b")
        assert a is not b

    def test_inherits_from_base_logger(self) -> None:
        assert isinstance(ConnectorLogger(), BaseLogger)


class TestModuleLevelLogger:
    def test_logger_is_connector_logger_instance(self) -> None:
        assert isinstance(logger, ConnectorLogger)

    def test_logger_default_name(self) -> None:
        assert logger._logger.name == "connector"
