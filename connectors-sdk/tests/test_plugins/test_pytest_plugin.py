"""Tests for the SDK's pytest plugin (`_connectors_sdk_plugins.pytest_plugin`)."""

import logging

import connectors_sdk.logger._logger as logger_module
from connectors_sdk.logger import configure_logging, get_logger


def test_plugin_should_keep_the_root_logger(monkeypatch, caplog):
    """Test that the SDK's logging setup leaves pytest's handlers and level alone."""
    monkeypatch.setattr(logger_module, "_logging_configured", False)
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")
    caplog.set_level(logging.INFO)
    root_logger = logging.getLogger()
    handlers = list(root_logger.handlers)

    get_logger("tests.demo").info("Hello")  # First record: setup from the env vars
    configure_logging(log_level="error", json_logging=True)  # Setup from the settings

    assert root_logger.handlers == handlers
    assert root_logger.level == logging.INFO
    assert [record.message for record in caplog.records] == ["Hello"]


def test_plugin_should_be_loaded_by_pytest(pytester):
    """Test that pytest loads the plugin through the SDK's entry point."""
    pytester.makepyfile("""
        import logging

        from connectors_sdk.logger import configure_logging, get_logger


        def test_caplog(caplog):
            caplog.set_level(logging.INFO)
            configure_logging(log_level="error", json_logging=True)
            get_logger("demo").info("Hello")
            assert [record.message for record in caplog.records] == ["Hello"]
        """)

    pytester.runpytest_subprocess().assert_outcomes(passed=1)
    pytester.runpytest_subprocess("-p", "no:connectors_sdk").assert_outcomes(failed=1)
