"""Tests for `connectors_sdk.logger`."""

import json
import logging

import connectors_sdk.logger
import pytest
from connectors_sdk.logger import ConnectorLoggerAdapter, get_logger
from pycti.utils.opencti_logger import CustomJsonFormatter


def _format_as_json(record: logging.LogRecord) -> dict:
    formatter = CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
    return json.loads(formatter.format(record))


def test_public_api():
    """Test that the module exposes the expected public API."""
    assert set(connectors_sdk.logger.__all__) == {
        "ConnectorLoggerAdapter",
        "configure_logging",
        "get_logger",
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


def test_logger_exception_should_attach_the_handled_exception(caplog):
    """Test that `exception()`, in an `except` block, logs the traceback and `meta`."""
    logger = get_logger("tests.demo")

    try:
        raise ValueError("boom")
    except ValueError:
        logger.exception("Something failed", meta={"error": "boom"})

    [record] = caplog.records
    assert record.levelno == logging.ERROR
    assert record.exc_info[0] is ValueError
    assert record.attributes == {"error": "boom"}


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
