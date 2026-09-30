"""Tests for `connectors_sdk.logger._logger`.

These cover the two promises of the SDK's logger: the `meta` keyword on the loggers it
hands out, and the fact that no other logger in the process is changed.
"""

import logging
import threading
from collections import Counter

import pytest
from connectors_sdk.logger._logger import (
    ExtendedLogger,
    get_extended_logger,
)


class RecordingHandler(logging.Handler):
    """Collect every record it is given."""

    def __init__(self):
        """Initialise an empty collection of records."""
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Store a record.

        Args:
            record (logging.LogRecord): The record to store.
        """
        self.records.append(record)


@pytest.fixture
def recorded():
    """Provide a claimed logger and the handler collecting its records.

    Returns:
        tuple[ExtendedLogger, RecordingHandler]: The logger and its handler.
    """
    logger = get_extended_logger("test_connector")
    logger.setLevel(logging.DEBUG)
    handler = RecordingHandler()
    logger.addHandler(handler)
    return logger, handler


def test_logger_should_move_metadata_into_attributes(recorded):
    """Test that `meta` reaches the record as `attributes`, where the formatter finds it."""
    # Given: A connector logger
    logger, handler = recorded

    # When: A message is logged with metadata
    logger.info("Fetched indicators", meta={"count": 42})

    # Then: The metadata is exposed as `attributes`
    assert handler.records[0].attributes == {"count": 42}


def test_logger_should_not_set_attributes_without_metadata(recorded):
    """Test that a plain call produces a record indistinguishable from a native one."""
    # Given: A connector logger
    logger, handler = recorded

    # When: A message is logged without metadata
    logger.info("Fetched indicators")

    # Then: No `attributes` field is added
    assert not hasattr(handler.records[0], "attributes")


@pytest.mark.parametrize(
    "method_name, expected_level",
    [
        pytest.param("debug", logging.DEBUG, id="debug"),
        pytest.param("info", logging.INFO, id="info"),
        pytest.param("warning", logging.WARNING, id="warning"),
        pytest.param("error", logging.ERROR, id="error"),
        pytest.param("critical", logging.CRITICAL, id="critical"),
    ],
)
def test_logger_should_accept_metadata_on_every_level(
    recorded, method_name, expected_level
):
    """Test that overriding `_log` alone covers all level methods."""
    # Given: A connector logger
    logger, handler = recorded

    # When: Each level method is called with metadata
    getattr(logger, method_name)("message", meta={"key": "value"})

    # Then: The record carries both the level and the metadata
    assert handler.records[0].levelno == expected_level
    assert handler.records[0].attributes == {"key": "value"}


def test_logger_should_attach_the_exception_to_an_exception_call(recorded):
    """Test that `exception()` keeps its standard behaviour alongside `meta`."""
    # Given: A connector logger inside an exception handler
    logger, handler = recorded

    # When: The exception is logged with metadata
    try:
        raise ValueError("boom")
    except ValueError:
        logger.exception("Import failed", meta={"stage": "fetch"})

    # Then: Both the exception and the metadata are recorded
    assert handler.records[0].exc_info[0] is ValueError
    assert handler.records[0].attributes == {"stage": "fetch"}


def test_logger_should_still_interpolate_percent_style_arguments(recorded):
    """Test that `meta` does not displace positional interpolation arguments.

    pycti's wrapper takes metadata positionally, which makes the two mutually exclusive.
    Passing it as a keyword keeps standard logging behaviour available.
    """
    # Given: A connector logger
    logger, handler = recorded

    # When: A message uses both interpolation and metadata
    logger.info("got %s items in %.2fs", 12, 0.5, meta={"source": "api"})

    # Then: The message is interpolated and the metadata is preserved
    assert handler.records[0].getMessage() == "got 12 items in 0.50s"
    assert handler.records[0].attributes == {"source": "api"}


def test_logger_should_merge_metadata_with_explicit_extra(recorded):
    """Test that `meta` and the standard `extra` argument coexist."""
    # Given: A connector logger
    logger, handler = recorded

    # When: Both are supplied
    logger.info("message", extra={"work_id": "work--1"}, meta={"count": 1})

    # Then: Neither displaces the other
    assert handler.records[0].work_id == "work--1"
    assert handler.records[0].attributes == {"count": 1}


def test_logger_should_report_the_real_caller(recorded):
    """Test that overriding `_log` does not make every record point at the SDK.

    The override adds a stack frame that `logging`'s caller detection cannot skip, since
    it lives outside `logging/__init__.py`. Without compensating, `funcName`, `lineno`
    and `pathname` would all name the SDK instead of the connector.
    """
    # Given: A connector logger
    logger, handler = recorded

    # When: A message is logged from this test
    logger.info("message", meta={"key": "value"})

    # Then: The record names this test, not the SDK
    assert handler.records[0].funcName == "test_logger_should_report_the_real_caller"
    assert handler.records[0].filename == "test_logger.py"


def test_get_extended_logger_should_return_the_logger_for_that_name():
    """Test that the SDK returns `logging`'s own singleton, not a wrapper around it."""
    # Given / When: A logger is requested
    logger = get_extended_logger("test_singleton")

    # Then: It is the object `logging` hands out for that name
    assert logger is logging.getLogger("test_singleton")
    assert isinstance(logger, ExtendedLogger)


def test_get_extended_logger_should_upgrade_a_logger_created_earlier():
    """Test that a module importing `logging` before the SDK still gets `meta`.

    Loggers are singletons per name, so upgrading re-points the object a module may
    already hold, rather than handing back a different one.
    """
    # Given: A logger created before the SDK is asked for it
    early = logging.getLogger("test_early")
    assert type(early) is logging.Logger

    # When: The SDK is asked for that name
    logger = get_extended_logger("test_early")

    # Then: The reference obtained earlier accepts metadata
    assert logger is early
    assert isinstance(early, ExtendedLogger)


def test_get_extended_logger_should_leave_other_loggers_alone():
    """Test that the SDK upgrades the logger it is asked for, and nothing else.

    A module calling `logging.getLogger` is asking for a standard logger, and a library
    has no business changing what the stdlib returns process-wide.
    """
    # Given: The SDK has been asked for one of its loggers
    get_extended_logger("test_scoped")

    # When: Other loggers are fetched through `logging` itself
    sibling = logging.getLogger("test_unrelated")
    child = logging.getLogger("test_scoped.child")

    # Then: They are stock loggers
    assert type(sibling) is logging.Logger
    assert type(child) is logging.Logger


def test_get_extended_logger_should_not_touch_the_logger_class():
    """Test that the class `logging` instantiates is left as it was.

    Changing it would turn every logger created afterwards into an SDK logger, even
    those of other libraries. A library must not do that to the application using it.
    """
    # Given / When: The SDK is asked for a logger
    get_extended_logger("test_logger_class")

    # Then: `logging` still builds stock loggers
    assert logging.getLoggerClass() is logging.Logger


def test_get_extended_logger_should_be_idempotent():
    """Test that asking twice changes nothing."""
    # Given: An already-upgraded logger
    logger = get_extended_logger("test_idempotent")

    # When: It is requested again
    again = get_extended_logger("test_idempotent")

    # Then: It is unchanged
    assert again is logger
    assert type(logger) is ExtendedLogger


def test_get_extended_logger_should_leave_a_foreign_logger_class_alone():
    """Test that a logger class installed by the host application is never clobbered.

    No library in the connectors ecosystem calls `logging.setLoggerClass`, so this is a
    safety net rather than a scenario we expect. Degrading to a plain logger is
    preferable to destroying someone else's behaviour.
    """

    # Given: A third party's logger class, and a logger built from it
    class ForeignLogger(logging.Logger):
        pass

    logging.setLoggerClass(ForeignLogger)
    foreign = logging.getLogger("test_foreign")

    # When: The SDK is asked for that same name
    get_extended_logger("test_foreign")

    # Then: Neither the class nor the logger built from it is touched
    assert logging.getLoggerClass() is ForeignLogger
    assert type(foreign) is ForeignLogger


def test_get_extended_logger_should_leave_the_registry_alone():
    """Test that the logger registry is never replaced.

    Hooking `logging.Logger.manager` would make every logger in the process an SDK one.
    The SDK maintains its own loggers and leaves the stdlib's behaviour untouched.
    """
    # Given: The stock registry
    registry = logging.Logger.manager

    # When: The SDK is asked for a logger
    get_extended_logger("test_registry")

    # Then: It is still the stock one
    assert type(registry) is logging.Manager
    assert logging.Logger.manager is registry


def test_get_child_should_return_a_connector_logger():
    """Test that a descendant of an SDK logger accepts metadata too.

    `logging.Logger.getChild` builds a stock logger, so this is behaviour the class has
    to add. It stays within what the SDK promises: a child of its logger is its logger.
    """
    # Given: A connector logger
    parent = get_extended_logger("test_get_child")

    # When: A child is fetched through it
    child = parent.getChild("converter")

    # Then: It accepts metadata
    assert isinstance(child, ExtendedLogger)
    assert child is logging.getLogger("test_get_child.converter")


def test_get_child_should_work_at_any_depth():
    """Test that `getChild` keeps working on a child of a child."""
    # Given: A connector logger
    parent = get_extended_logger("test_deep_child")

    # When: Children are chained
    grandchild = parent.getChild("client").getChild("api")

    # Then: The deepest one still accepts metadata
    assert isinstance(grandchild, ExtendedLogger)
    assert grandchild is logging.getLogger("test_deep_child.client.api")


def test_logger_creation_should_be_thread_safe():
    """Test that loggers created at the same time all accept metadata.

    Connectors run several threads. pycti alone runs `ListenQueue`, `PingAlive` and
    `StreamAlive`. Upgrading a logger can be done twice without harm, and happens after
    `logging` released its own lock, so no logger can be left behind.
    """
    # Given: Two threads asking the SDK for loggers
    seen: Counter = Counter()

    def create_loggers(prefix):
        for index in range(500):
            seen[type(get_extended_logger(f"{prefix}.t{index}")).__name__] += 1

    # When: Both run concurrently
    threads = [
        threading.Thread(target=create_loggers, args=("test_threaded",)),
        threading.Thread(target=create_loggers, args=("test_other",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Then: Every one of them accepts metadata
    assert seen == Counter({"ExtendedLogger": 1000})
