"""Tests for the public functions of `connectors_sdk.logger`.

These check what `get_connector_logger` and `get_sdk_logger` return: the class, the
name, the handler set on the namespace, and the fact that no other logger is changed.
"""

import io
import json
import logging

import pytest
from connectors_sdk.logger import get_connector_logger, get_sdk_logger
from connectors_sdk.logger._logger import ExtendedLogger
from pycti.utils.opencti_logger import CustomJsonFormatter


@pytest.fixture(autouse=True)
def without_level_environment_variable(monkeypatch):
    """Ensure the developer's own `CONNECTOR_LOG_LEVEL` cannot influence the tests."""
    monkeypatch.delenv("CONNECTOR_LOG_LEVEL", raising=False)


def sdk_handlers(namespace: str) -> list[logging.Handler]:
    """Return the handlers the SDK installed on `namespace`.

    pytest attaches its own capture handlers directly to non-propagating loggers, so
    counting `logger.handlers` would measure the test runner too; the JSON formatter is
    what identifies a handler as ours.
    """
    return [
        handler
        for handler in logging.getLogger(namespace).handlers
        if isinstance(handler.formatter, CustomJsonFormatter)
    ]


@pytest.mark.parametrize(
    "get_logger",
    [
        pytest.param(get_connector_logger, id="connector"),
        pytest.param(get_sdk_logger, id="sdk"),
    ],
)
def test_get_logger_should_return_a_logger_accepting_metadata(
    mock_main_path, get_logger
):
    """Test that both entry points yield a logger accepting `meta`."""
    # Given / When: A logger is requested
    logger = get_logger("test_entry_point")

    # Then: It accepts metadata
    assert isinstance(logger, ExtendedLogger)


@pytest.mark.parametrize(
    ("get_logger", "expected_name"),
    [
        pytest.param(get_connector_logger, "connector.demo", id="connector"),
        pytest.param(get_sdk_logger, "connectors_sdk.demo", id="sdk"),
    ],
)
def test_get_logger_should_place_the_logger_under_its_namespace(
    mock_main_path, get_logger, expected_name
):
    """Test that the caller's name is nested under the namespace the SDK owns.

    The namespace is what makes the SDK's own records separable from the connector's:
    raising or silencing one leaves the other alone.
    """
    # Given / When: A logger is requested
    logger = get_logger("demo")

    # Then: Its name is prefixed with the namespace
    assert logger.name == expected_name


def test_get_logger_should_make_children_usable_too(mock_main_path):
    """Test that a descendant of an SDK logger accepts metadata as well."""
    # Given: An SDK logger
    parent = get_connector_logger("test_children")

    # When: A child is obtained through it
    child = parent.getChild("converter")

    # Then: It accepts metadata
    assert isinstance(child, ExtendedLogger)


def test_get_logger_should_leave_native_loggers_alone(mock_main_path):
    """Test that the SDK never changes what `logging.getLogger` returns.

    A module calling `logging` directly is asking for a standard logger, and should get
    what Python documents rather than something the SDK substituted process-wide.
    """
    # Given: The SDK has been asked for a logger
    get_connector_logger("test_native_untouched")

    # When: An unrelated logger is fetched through `logging` itself
    native = logging.getLogger("test_native_untouched")

    # Then: It is a stock logger
    assert type(native) is logging.Logger


def test_get_logger_should_not_overrule_a_logger_class_set_by_the_host(mock_main_path):
    """Test that an application's own logger class is never discarded.

    Re-pointing `__class__` would throw that class' behaviour away, which is a worse
    outcome than logging without `meta`.
    """

    # Given: A host application that installed its own logger class
    class HostLogger(logging.Logger):
        pass

    logging.setLoggerClass(HostLogger)

    # When: The SDK is asked for a logger in that process
    logger = get_connector_logger("test_host_class")

    # Then: The host's class stands
    assert type(logger) is HostLogger


def test_get_logger_should_install_the_json_handler_on_the_namespace(mock_main_path):
    """Test that the namespace is configured with OpenCTI's JSON format."""
    # Given / When: A logger is requested
    get_connector_logger("test_setup")

    # Then: A single handler on the namespace renders records as OpenCTI JSON
    assert len(sdk_handlers("connector")) == 1


def test_get_logger_should_install_the_handler_once(mock_main_path):
    """Test that repeated calls do not stack handlers."""
    # Given / When: Loggers are requested several times
    get_connector_logger("test_setup")
    get_connector_logger("test_setup")
    get_connector_logger("test_other_module")

    # Then: Only one handler is installed
    assert len(sdk_handlers("connector")) == 1


def test_get_logger_should_leave_the_root_logger_alone(mock_main_path):
    """Test that the host's own logging configuration is untouched.

    The SDK configures the namespaces it owns and nothing else, so a connector, a test
    runner or pycti remains free to set the root logger up as it sees fit.
    """
    # Given: A root logger in a known state
    root_logger = logging.getLogger()
    handler_count = len(root_logger.handlers)
    root_level = root_logger.level

    # When: A logger is requested and a record emitted, exercising the whole setup
    get_connector_logger("test_setup").error("resolve now")

    # Then: The root logger is as it was
    assert len(root_logger.handlers) == handler_count
    assert root_logger.level == root_level


def test_get_logger_should_not_propagate_to_the_root_logger(mock_main_path):
    """Test that records stop at the namespace.

    `pycti` calls `logging.basicConfig(..., force=True)` when a helper is built, so a
    propagating record would reach that handler as well and be written twice.
    """
    # Given / When: A logger is requested
    get_connector_logger("test_setup")

    # Then: Its namespace does not hand records to the root logger
    assert logging.getLogger("connector").propagate is False


def test_get_logger_should_let_each_namespace_be_levelled_apart(mock_main_path):
    """Test that the two namespaces carry their own handler.

    Silencing the SDK's internals without silencing the connector is only possible if
    the two are configured separately.
    """
    # Given / When: A logger is requested from each entry point
    get_connector_logger("test_apart")
    get_sdk_logger("test_apart")

    # Then: Each namespace has its own handler
    connector_handlers = sdk_handlers("connector")
    namespace_handlers = sdk_handlers("connectors_sdk")
    assert len(connector_handlers) == 1
    assert len(namespace_handlers) == 1
    assert connector_handlers[0] is not namespace_handlers[0]


def test_get_logger_should_ignore_an_unknown_level_in_the_configuration(
    monkeypatch, mock_main_path
):
    """Test that an unusable configured level falls back rather than raising.

    That value has not been through settings validation yet, so it can be anything.
    Settings rejects it later with a proper configuration error; logging must not fail
    first, and must not be left unconfigured.
    """
    # Given: A configuration naming a level that does not exist
    monkeypatch.setenv("CONNECTOR_LOG_LEVEL", "verbose")
    logger = get_connector_logger("test_setup")

    # When: A record is emitted, forcing the level to be read
    logger.error("resolve now")

    # Then: The default is applied
    assert logger.getEffectiveLevel() == logging.ERROR


def test_logging_should_produce_opencti_json_end_to_end(mock_main_path):
    """Test the whole pipeline, from `get_connector_logger` to the bytes written out."""
    # Given: A connector logger set to an emitting level, writing to a readable stream
    logger = get_connector_logger("test_end_to_end")
    logging.getLogger("connector").setLevel("INFO")
    # The handler binds `sys.stderr` when the first logger is requested, so it escapes
    # any capture installed later. Reading its stream is the only way to see its output.
    handler = sdk_handlers("connector")[0]
    stream = io.StringIO()
    handler.setStream(stream)

    # When: A module below it logs with metadata
    logger.getChild("client").info("Fetched indicators", meta={"count": 42})

    # Then: A single OpenCTI JSON document is written
    output = stream.getvalue().strip()
    assert "\n" not in output
    assert json.loads(output) == {
        "timestamp": json.loads(output)["timestamp"],
        "level": "INFO",
        "name": "connector.test_end_to_end.client",
        "message": "Fetched indicators",
        "attributes": {"count": 42},
    }
    assert json.loads(output) == {
        "timestamp": json.loads(output)["timestamp"],
        "level": "INFO",
        "name": "connector.test_end_to_end.client",
        "message": "Fetched indicators",
        "attributes": {"count": 42},
    }
