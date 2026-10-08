"""Tests for `connectors_sdk.logger`."""

import importlib
import json
import logging

import connectors_sdk.logger
import pytest
from connectors_sdk.logger import ConnectorLoggerAdapter, get_logger, set_log_level
from connectors_sdk.logger._logger import configure_logging
from pycti.utils.opencti_logger import CustomJsonFormatter
from pycti.utils.opencti_logger import logger as pycti_logger


def _json_handlers() -> list[logging.Handler]:
    return [
        handler
        for handler in logging.getLogger().handlers
        if isinstance(handler.formatter, CustomJsonFormatter)
    ]


def _format_as_json(record: logging.LogRecord) -> dict:
    formatter = CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
    return json.loads(formatter.format(record))


def test_public_api():
    """Test that the module exposes the expected public API."""
    assert set(connectors_sdk.logger.__all__) == {
        "ConnectorLoggerAdapter",
        "get_logger",
        "set_log_level",
    }


def test_get_logger_should_wrap_the_standard_logger():
    """Test that `get_logger` returns an adapter around `logging.getLogger(name)`."""
    logger = get_logger("tests.demo")

    assert isinstance(logger, ConnectorLoggerAdapter)
    assert isinstance(logger, logging.LoggerAdapter)
    assert not isinstance(logger, logging.Logger)  # documented in the public API
    assert logger.logger is logging.getLogger("tests.demo")
    assert logger.name == "tests.demo"


@pytest.mark.parametrize(
    "method_name, level",
    [
        ("debug", logging.DEBUG),
        ("info", logging.INFO),
        ("warning", logging.WARNING),
        ("error", logging.ERROR),
        ("critical", logging.CRITICAL),
    ],
)
def test_logger_should_put_meta_in_attributes(caplog, method_name, level):
    """Test that `meta` ends up in the record's `attributes` field, at every level."""
    caplog.set_level(logging.DEBUG)
    logger = get_logger("tests.demo")

    getattr(logger, method_name)("Hello", meta={"count": 42})

    [record] = caplog.records
    assert record.levelno == level
    assert record.getMessage() == "Hello"
    assert record.attributes == {"count": 42}


def test_logger_should_merge_meta_with_extra(caplog):
    """Test that `meta` does not replace other `extra` fields."""
    caplog.set_level(logging.INFO)

    get_logger("tests.demo").info("Hello", extra={"other": 1}, meta={"count": 42})

    [record] = caplog.records
    assert record.other == 1
    assert record.attributes == {"count": 42}


def test_logger_without_meta_should_not_set_attributes(caplog):
    """Test that a record logged without `meta` has no `attributes` field."""
    caplog.set_level(logging.INFO)

    get_logger("tests.demo").info("Hello %s", "world")

    [record] = caplog.records
    assert record.getMessage() == "Hello world"
    assert not hasattr(record, "attributes")


@pytest.mark.parametrize(
    "method_name", ["debug", "info", "warning", "error", "critical", "exception"]
)
def test_logger_should_report_the_caller_location(caplog, method_name):
    """Test that records point at the logging call, not at the adapter."""
    caplog.set_level(logging.DEBUG)

    getattr(get_logger("tests.demo"), method_name)("Hello", meta={"count": 42})

    [record] = caplog.records
    assert record.filename == "test_logger.py"
    assert record.funcName == "test_logger_should_report_the_caller_location"


def test_logger_error_should_respect_an_explicit_stacklevel(caplog):
    """Test that a caller's own `stacklevel` is kept when calling `error()`."""

    def log_helper():
        get_logger("tests.demo").error("Hello", stacklevel=2)

    log_helper()

    [record] = caplog.records
    assert record.funcName == "test_logger_error_should_respect_an_explicit_stacklevel"


def test_logger_error_should_attach_the_handled_exception(caplog):
    """Test that `error()` attaches the traceback when an exception is being handled."""
    logger = get_logger("tests.demo")

    try:
        raise ValueError("boom")
    except ValueError:
        logger.error("Something failed", meta={"error": "boom"})

    [record] = caplog.records
    assert record.exc_info is not None
    assert record.exc_info[0] is ValueError
    assert record.attributes == {"error": "boom"}


def test_logger_error_should_not_attach_anything_outside_except(caplog):
    """Test that `error()` adds no empty traceback when no exception is handled."""
    get_logger("tests.demo").error("Something failed")

    [record] = caplog.records
    assert record.exc_info is None


def test_logger_error_should_respect_an_explicit_exc_info(caplog):
    """Test that an explicit `exc_info` is never overridden."""
    logger = get_logger("tests.demo")

    try:
        raise ValueError("boom")
    except ValueError:
        logger.error("Something failed", exc_info=False)

    [record] = caplog.records
    assert not record.exc_info


def test_logger_records_should_propagate_to_the_root_logger(caplog):
    """Test that records reach root handlers (`caplog`, OpenTelemetry, ...)."""
    caplog.set_level(logging.INFO)

    get_logger("connectors_sdk.demo").info("From the SDK")
    get_logger("connector.demo").info("From a connector")
    logging.getLogger("connector.client").info("From a standard logger")

    assert [record.getMessage() for record in caplog.records] == [
        "From the SDK",
        "From a connector",
        "From a standard logger",
    ]


def test_logger_json_output_should_match_pycti(caplog):
    """Test that a record is formatted exactly like one of pycti's `AppLogger`."""
    caplog.set_level(logging.INFO)

    get_logger("tests.demo").info("Hello", meta={"count": 42})
    # What pycti's `AppLogger.info(message, meta)` does
    logging.getLogger("tests.demo").info("Hello", extra={"attributes": {"count": 42}})

    sdk_output, pycti_output = (_format_as_json(r) for r in caplog.records)
    sdk_output.pop("timestamp")
    pycti_output.pop("timestamp")
    assert sdk_output == pycti_output
    assert sdk_output == {
        "level": "INFO",
        "name": "tests.demo",
        "message": "Hello",
        "attributes": {"count": 42},
    }


def test_configure_logging_should_add_a_single_json_handler(monkeypatch):
    """Test that `configure_logging` is idempotent."""
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")
    for handler in _json_handlers():
        logging.getLogger().removeHandler(handler)

    configure_logging()
    configure_logging()

    [handler] = _json_handlers()
    assert isinstance(handler, logging.StreamHandler)


def test_configure_logging_should_not_duplicate_pycti_handler(monkeypatch):
    """Test that no handler is added once pycti has configured the root logger."""
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")
    third_party_levels = {
        name: logging.getLogger(name).level for name in ("urllib3", "pika")
    }
    try:
        # What `OpenCTIConnectorHelper` does on creation
        pycti_logger(logging.INFO)
        [pycti_handler] = _json_handlers()

        configure_logging()

        assert _json_handlers() == [pycti_handler]
    finally:
        for name, level in third_party_levels.items():
            logging.getLogger(name).setLevel(level)


@pytest.mark.parametrize(
    "env_value, expected_level",
    [
        ("debug", logging.DEBUG),
        ("INFO", logging.INFO),
        ("warn", logging.WARNING),
        ("warning", logging.WARNING),
        ("error", logging.ERROR),
        ("not-a-level", logging.ERROR),
    ],
)
def test_configure_logging_should_read_level_from_env(
    monkeypatch, env_value, expected_level
):
    """Test that the level comes from `CONNECTOR_LOG_LEVEL`, with pycti's default."""
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", env_value)

    configure_logging()

    assert logging.getLogger().level == expected_level


def test_configure_logging_should_default_to_error_without_env(monkeypatch):
    """Test that the level defaults to pycti's default when nothing configures it."""
    monkeypatch.delenv("CONNECTOR_LOG_LEVEL", raising=False)

    with pytest.warns(UserWarning, match="CONNECTOR_LOG_LEVEL is not set"):
        configure_logging()

    assert logging.getLogger().level == logging.ERROR


@pytest.mark.parametrize("env_value", [None, ""])
def test_configure_logging_should_warn_when_env_var_is_missing(
    monkeypatch, caplog, env_value
):
    """Test that a missing level is reported with a Python warning, not a log record."""
    if env_value is None:
        monkeypatch.delenv("CONNECTOR_LOG_LEVEL", raising=False)
    else:
        monkeypatch.setenv("CONNECTOR_LOG_LEVEL", env_value)

    with pytest.warns(UserWarning) as warning_records:
        configure_logging()

    [warning] = warning_records
    assert str(warning.message) == (
        "CONNECTOR_LOG_LEVEL is not set: the default log level ('error') applies "
        "until the connector's settings are validated."
    )
    assert caplog.records == []
    assert logging.getLogger().level == logging.ERROR


def test_configure_logging_should_not_warn_when_env_var_is_set(monkeypatch, recwarn):
    """Test that no warning is emitted when `CONNECTOR_LOG_LEVEL` is set."""
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "debug")

    configure_logging()

    assert [w for w in recwarn if w.category is UserWarning] == []


def test_importing_the_module_should_configure_logging(monkeypatch):
    """Test that logging is set up as soon as `connectors_sdk.logger` is imported."""
    for handler in _json_handlers():
        logging.getLogger().removeHandler(handler)
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "info")

    importlib.reload(connectors_sdk.logger)

    assert len(_json_handlers()) == 1
    assert logging.getLogger().level == logging.INFO


@pytest.mark.parametrize(
    "level, expected_level",
    [
        ("debug", logging.DEBUG),
        ("warn", logging.WARNING),
        ("not-a-level", logging.ERROR),
    ],
)
def test_set_log_level_should_set_root_level(level, expected_level):
    """Test that `set_log_level` sets the root logger's level."""
    set_log_level(level)

    assert logging.getLogger().level == expected_level
