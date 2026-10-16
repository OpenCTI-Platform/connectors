"""Tests for `connectors_sdk.logger`."""

import json
import logging
import os
import subprocess
import sys

import connectors_sdk.logger
import pytest
from connectors_sdk.logger import ConnectorLoggerAdapter, get_logger, set_log_level
from connectors_sdk.logger._logger import _configure_logging
from pycti.connector.opencti_connector_helper import get_config_variable
from pycti.utils.opencti_logger import CustomJsonFormatter
from pycti.utils.opencti_logger import logger as pycti_logger


@pytest.fixture(autouse=True)
def default_json_logging(monkeypatch):
    """Run every test with pycti's default JSON logging, whatever the shell sets."""
    monkeypatch.delenv("OPENCTI_JSON_LOGGING", raising=False)


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


@pytest.mark.parametrize(
    "env_value",
    [None, "", "true", "True", "yes", "0", "1", "FALSE", "false", "False", "no"],
)
def test_configure_logging_should_choose_json_logging_like_pycti(
    monkeypatch, env_value
):
    """Test that `OPENCTI_JSON_LOGGING` enables JSON exactly when pycti's helper does."""
    if env_value is None:
        monkeypatch.delenv("OPENCTI_JSON_LOGGING", raising=False)
    else:
        monkeypatch.setenv("OPENCTI_JSON_LOGGING", env_value)
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")
    # What `OpenCTIConnectorHelper` does, then passes to pycti's `logger()`
    pycti_json_logging = get_config_variable(
        "OPENCTI_JSON_LOGGING", ["opencti", "json_logging"], {}, False, True
    )
    root_logger = logging.getLogger()
    saved_handlers = list(root_logger.handlers)
    # `logging.basicConfig()` only configures a root logger that has no handler yet
    root_logger.handlers.clear()
    try:
        _configure_logging()

        assert bool(_json_handlers()) is bool(pycti_json_logging)
    finally:
        root_logger.handlers[:] = saved_handlers


@pytest.mark.parametrize("env_value", ["false", "False", "no"])
def test_configure_logging_should_write_plain_text_when_json_logging_is_disabled(
    monkeypatch, env_value
):
    """Test that disabling JSON logging gives pycti's plain text format for the run."""
    monkeypatch.setenv("OPENCTI_JSON_LOGGING", env_value)
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")
    root_logger = logging.getLogger()
    saved_handlers = list(root_logger.handlers)
    third_party_levels = {
        name: logging.getLogger(name).level for name in ("urllib3", "pika")
    }
    # `logging.basicConfig()` only configures a root logger that has no handler yet
    root_logger.handlers.clear()
    try:
        _configure_logging()
        [handler] = root_logger.handlers
        assert not isinstance(handler.formatter, CustomJsonFormatter)
        assert handler.formatter._fmt == logging.BASIC_FORMAT

        # What `OpenCTIConnectorHelper` does on creation, in non-JSON mode
        pycti_logger(logging.INFO, False)

        assert root_logger.handlers == [handler]
    finally:
        root_logger.handlers[:] = saved_handlers
        for name, level in third_party_levels.items():
            logging.getLogger(name).setLevel(level)


def test_configure_logging_should_add_a_single_json_handler(monkeypatch):
    """Test that `_configure_logging` is idempotent."""
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "error")
    for handler in _json_handlers():
        logging.getLogger().removeHandler(handler)

    _configure_logging()
    _configure_logging()

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

        _configure_logging()

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

    _configure_logging()

    assert logging.getLogger().level == expected_level


def test_configure_logging_should_default_to_error_without_env(monkeypatch):
    """Test that the level defaults to pycti's default when nothing configures it."""
    monkeypatch.delenv("CONNECTOR_LOG_LEVEL", raising=False)

    with pytest.warns(UserWarning, match="CONNECTOR_LOG_LEVEL is not set"):
        _configure_logging()

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
        _configure_logging()

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

    _configure_logging()

    assert [w for w in recwarn if w.category is UserWarning] == []


def test_importing_the_module_should_configure_logging():
    """Test that logging is set up as soon as `connectors_sdk.logger` is imported."""
    # A fresh interpreter, since this process imported the module long ago
    script = (
        "import logging\n"
        "from pycti.utils.opencti_logger import CustomJsonFormatter\n"
        "import connectors_sdk.logger\n"
        "root = logging.getLogger()\n"
        "json_handlers = [\n"
        "    h for h in root.handlers if isinstance(h.formatter, CustomJsonFormatter)\n"
        "]\n"
        "print(len(json_handlers), logging.getLevelName(root.level))\n"
    )

    result = subprocess.run(  # noqa: S603 - fixed script, current interpreter
        [sys.executable, "-c", script],
        env={**os.environ, "CONNECTOR_LOG_LEVEL": "info"},
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.split() == ["1", "INFO"]


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
