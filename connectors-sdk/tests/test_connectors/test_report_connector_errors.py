"""Offer tests for the decorator that reports the errors of an external import run."""

import logging

import pytest
from connectors_sdk import report_connector_errors
from connectors_sdk.exceptions.connector_errors import (
    DataConversionError,
    DataNotFoundError,
    ProviderApiTimeoutError,
)
from connectors_sdk.exceptions.error_store import ErrorStore

LOGGER_NAME = "connectors_sdk.connectors.external_import.report_connector_errors"


@pytest.fixture(autouse=True)
def not_recording():
    """Stop recording and empty the shared store before and after each test."""
    ErrorStore().stop_recording()
    yield
    ErrorStore().stop_recording()


def _recording_is_off() -> bool:
    """Tell whether the store keeps nothing, i.e. it is not recording."""
    DataConversionError("created after the call")
    return ErrorStore().get_errors() == []


def test_call_without_error_returns_none_and_raises_nothing():
    """Test that a call without error returns None and raises nothing."""
    # Given a callback that returns a list and creates no error
    callback = report_connector_errors(lambda: [{"code": "api.timeout"}])
    # When calling it
    result = callback()
    # Then it should return None, so pycti reads no returned error list
    assert result is None
    assert _recording_is_off()


def test_arguments_are_passed_to_the_callback():
    """Test that the decorated function receives the arguments it is called with."""
    # Given a callback that keeps its arguments
    received = []

    @report_connector_errors
    def process_message(first, second, keyword=None):
        received.append((first, second, keyword))

    # When calling it with positional and keyword arguments
    process_message(1, 2, keyword=3)
    # Then the callback should receive them
    assert received == [(1, 2, 3)]


def test_decorated_function_keeps_its_name():
    """Test that the decorated function looks like the callback."""

    # Given a decorated callback
    @report_connector_errors
    def process_message():
        """Run the connector once."""

    # Then its name and docstring should be kept
    assert process_message.__name__ == "process_message"
    assert process_message.__doc__ == "Run the connector once."


def test_unexpected_error_is_logged_and_reported_as_it_is(caplog):
    """Test that an unexpected exception is reported as it is, not wrapped."""
    # Given a callback raising an unexpected exception
    error = ValueError("boom")

    @report_connector_errors
    def process_message():
        raise error

    # When calling it
    with caplog.at_level(logging.ERROR, logger=LOGGER_NAME):
        with pytest.raises(ExceptionGroup) as exc_info:
            process_message()
    # Then the group should hold the exception itself
    assert exc_info.value.exceptions == (error,)
    # And the failure should be logged with its traceback
    [record] = [r for r in caplog.records if r.name == LOGGER_NAME]
    assert record.levelno == logging.ERROR
    assert record.getMessage() == "Connector's run failed"
    assert record.attributes == {"error": "boom"}
    assert record.exc_info[1] is error
    assert _recording_is_off()


def test_raised_connector_error_is_reported_once():
    """Test that a raised ConnectorError is not recorded a second time."""
    # Given a callback raising a ConnectorError, which records itself when created
    created = []

    @report_connector_errors
    def process_message():
        created.append(ProviderApiTimeoutError("too slow"))
        raise created[0]

    # When calling it
    with pytest.raises(ExceptionGroup) as exc_info:
        process_message()
    # Then the group should hold the error once
    assert exc_info.value.exceptions == (created[0],)


def test_handled_errors_and_failure_are_reported_in_order():
    """Test that handled errors are reported with the error that ends the call."""
    # Given a callback that handles an error, then fails
    handled = []
    failure = KeyError("missing")

    @report_connector_errors
    def process_message():
        try:
            raise DataConversionError("bad item")
        except DataConversionError as err:
            handled.append(err)  # the item is skipped
        raise failure

    # When calling it
    with pytest.raises(ExceptionGroup) as exc_info:
        process_message()
    # Then the group should hold both errors, in the order they were recorded
    assert exc_info.value.exceptions == (handled[0], failure)


def test_warning_only_call_raises_the_group():
    """Test that a call with WARNING errors only still raises them."""
    # Given a callback that creates two WARNING errors and ends normally
    created = []

    @report_connector_errors
    def process_message():
        created.append(DataConversionError("bad item"))
        created.append(DataNotFoundError("no item"))

    # When calling it
    with pytest.raises(ExceptionGroup) as exc_info:
        process_message()
    # Then the group should hold both errors
    assert exc_info.value.exceptions == tuple(created)
    assert exc_info.value.message == "Errors during the connector's run"
    assert _recording_is_off()


def test_errors_of_a_previous_call_are_not_reported_again():
    """Test that each call reports only its own errors."""
    # Given a callback that fails on its first call only
    calls = []

    @report_connector_errors
    def process_message():
        calls.append(None)
        if len(calls) == 1:
            raise ValueError("first call fails")

    with pytest.raises(ExceptionGroup):
        process_message()
    # When calling it again
    # Then the second call should raise nothing
    process_message()


def test_errors_created_outside_a_call_are_not_reported():
    """Test that an error created before the call is not reported by the call."""
    # Given an error created while the store is not recording
    DataConversionError("before the call")
    # When calling a callback without error
    # Then nothing should be raised
    report_connector_errors(lambda: None)()


def test_connector_error_created_before_the_call_is_reported_when_raised():
    """Test that a raised ConnectorError is reported, wherever it was created."""
    # Given a ConnectorError created while the store is not recording
    error = ProviderApiTimeoutError("too slow")

    @report_connector_errors
    def process_message():
        raise error

    # When a callback raises it
    with pytest.raises(ExceptionGroup) as exc_info:
        process_message()
    # Then the group should hold it
    assert exc_info.value.exceptions == (error,)


@pytest.mark.parametrize(
    "stop",
    [KeyboardInterrupt(), SystemExit(3)],
    ids=["keyboard_interrupt", "system_exit"],
)
def test_stop_is_logged_reraised_and_not_recorded(caplog, stop):
    """Test that a stop is re-raised as it is, even after errors in the call."""

    # Given a callback that creates an error, then is stopped
    @report_connector_errors
    def process_message():
        DataConversionError("bad item")
        raise stop

    # When calling it
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        with pytest.raises(type(stop)) as exc_info:
            process_message()
    # Then the stop itself should be raised, not an ExceptionGroup, so the exit
    # code of a SystemExit is kept
    assert exc_info.value is stop
    # And it should be logged
    [record] = [r for r in caplog.records if r.name == LOGGER_NAME]
    assert record.levelno == logging.INFO
    assert record.getMessage() == "Connector stopped by user or system"
    # And recording should be off, with nothing kept
    assert _recording_is_off()


class _Connector:
    """Connector with a decorated callback."""

    def __init__(self):
        self.calls = 0

    @report_connector_errors
    def process_message(self, fail: bool = False) -> None:
        self.calls += 1
        if fail:
            raise ValueError("boom")

    def callback(self) -> None:
        raise ValueError("bound boom")


def test_decorator_works_on_a_method():
    """Test that the decorator works on a method definition."""
    # Given a connector with a decorated method
    connector = _Connector()
    # When calling it, without and with an error
    connector.process_message()
    with pytest.raises(ExceptionGroup) as exc_info:
        connector.process_message(fail=True)
    # Then the method should receive its instance and report the error
    assert connector.calls == 2
    assert str(exc_info.value.exceptions[0]) == "boom"


def test_decorator_works_on_a_bound_method():
    """Test that the decorator works on a bound method."""
    # Given a bound method wrapped by the decorator
    callback = report_connector_errors(_Connector().callback)
    # When calling it
    with pytest.raises(ExceptionGroup) as exc_info:
        callback()
    # Then the error should be reported
    assert str(exc_info.value.exceptions[0]) == "bound boom"
