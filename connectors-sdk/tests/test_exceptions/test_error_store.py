"""Offer tests for the store of connector errors."""

import threading

import pytest
from connectors_sdk.exceptions.connector_errors import (
    DataConversionError,
    ProviderApiTimeoutError,
)
from connectors_sdk.exceptions.error_store import ErrorStore

THREADS = 8


@pytest.fixture(autouse=True)
def recording_off():
    """Stop recording and empty the shared store before and after each test."""
    ErrorStore().stop_recording()
    yield
    ErrorStore().stop_recording()


def _run_in_threads(target) -> None:
    """Run `target` in several threads released at the same time."""
    barrier = threading.Barrier(THREADS)

    def run():
        barrier.wait()
        target()

    threads = [threading.Thread(target=run) for _ in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def test_store_is_the_same_instance_everywhere():
    """Test that every call returns the same store."""
    # When getting the store twice
    # Then both references should be the same object
    assert ErrorStore() is ErrorStore()


def test_getting_the_store_again_keeps_its_errors():
    """Test that calling ErrorStore() again does not reset it."""
    # Given an error recorded while recording
    ErrorStore().start_recording()
    error = DataConversionError("bad item")
    ErrorStore().record_error(error)
    # When getting the store again
    store = ErrorStore()
    # Then the error should still be there
    assert store.get_errors() == [error]


def test_concurrent_first_creation_returns_one_instance(monkeypatch):
    """Test that threads creating the store at the same time get the same one."""
    # Given no store created yet
    monkeypatch.setattr(ErrorStore, "_instance", None)
    stores = []
    # When several threads create it at the same time
    _run_in_threads(lambda: stores.append(ErrorStore()))
    # Then they should all receive the same instance
    assert len(stores) == THREADS
    assert all(store is stores[0] for store in stores)


def test_new_store_does_not_record(monkeypatch):
    """Test that a new store keeps nothing until recording starts."""
    # Given a new store
    monkeypatch.setattr(ErrorStore, "_instance", None)
    # When an error is recorded
    ErrorStore().record_error(DataConversionError("bad item"))
    # Then nothing should be kept
    assert ErrorStore().get_errors() == []


def test_record_error_while_recording():
    """Test that an error recorded while recording is kept."""
    # Given recording on
    ErrorStore().start_recording()
    # When recording an error
    error = DataConversionError("bad item")
    ErrorStore().record_error(error)
    # Then it should be returned
    assert ErrorStore().stop_recording() == [error]


def test_record_error_while_not_recording_keeps_nothing():
    """Test that record_error keeps nothing and does not raise when not recording."""
    # Given recording off
    # When recording an error by hand
    ErrorStore().record_error(ValueError("x"))
    # Then nothing should be kept
    assert ErrorStore().get_errors() == []


def test_errors_recorded_after_stop_recording_are_not_kept():
    """Test that stop_recording turns recording off."""
    # Given recording started then stopped
    ErrorStore().start_recording()
    ErrorStore().stop_recording()
    # When recording an error
    ErrorStore().record_error(DataConversionError("too late"))
    # Then nothing should be kept
    assert ErrorStore().get_errors() == []


def test_start_recording_discards_previous_errors():
    """Test that starting to record empties the store."""
    # Given an error left by a previous call that never stopped recording
    ErrorStore().start_recording()
    ErrorStore().record_error(DataConversionError("previous call"))
    # When starting to record again
    ErrorStore().start_recording()
    # Then only the new errors should be returned
    error = ProviderApiTimeoutError("this call")
    ErrorStore().record_error(error)
    assert ErrorStore().stop_recording() == [error]


def test_stop_recording_returns_the_errors_in_recording_order():
    """Test that stop_recording returns the recorded objects, in order."""
    # Given two errors recorded while recording
    ErrorStore().start_recording()
    first = DataConversionError("bad item")
    second = ProviderApiTimeoutError("timed out")
    ErrorStore().record_error(first)
    ErrorStore().record_error(second)
    # When stopping recording
    errors = ErrorStore().stop_recording()
    # Then they should be the same objects, in recording order
    assert len(errors) == 2
    assert errors[0] is first
    assert errors[1] is second


def test_stop_recording_empties_the_store_and_returns_a_new_list():
    """Test that the returned list is detached from the store."""
    # Given an error recorded while recording
    ErrorStore().start_recording()
    error = DataConversionError("bad item")
    ErrorStore().record_error(error)
    # When stopping recording
    errors = ErrorStore().stop_recording()
    # Then the store should be empty
    assert ErrorStore().get_errors() == []
    # And changing the returned list should not change the store
    errors.append(ValueError("x"))
    assert ErrorStore().get_errors() == []
    assert errors[0] is error


def test_stop_recording_when_not_recording_returns_an_empty_list():
    """Test that stopping when recording is off returns an empty list."""
    # Given recording off
    # Then closing should return an empty list
    assert ErrorStore().stop_recording() == []


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(ValueError("x"), id="builtin_exception"),
        pytest.param(KeyError("missing"), id="lookup_error"),
    ],
)
def test_record_error_accepts_any_exception(error):
    """Test that an exception that is not a ConnectorError is kept as it is."""
    # Given recording on
    ErrorStore().start_recording()
    # When recording another exception
    ErrorStore().record_error(error)
    # Then it should be returned as it is
    errors = ErrorStore().stop_recording()
    assert len(errors) == 1
    assert errors[0] is error


def test_same_error_recorded_twice_is_kept_twice():
    """Test that the store does not deduplicate."""
    # Given an error recorded twice while recording
    ErrorStore().start_recording()
    error = ValueError("x")
    ErrorStore().record_error(error)
    ErrorStore().record_error(error)
    # Then it should be returned twice
    assert ErrorStore().stop_recording() == [error, error]


def test_get_errors_returns_a_copy():
    """Test that changing the returned list does not change the store."""
    # Given an error recorded while recording
    ErrorStore().start_recording()
    error = DataConversionError("bad item")
    ErrorStore().record_error(error)
    # When clearing the returned list
    ErrorStore().get_errors().clear()
    # Then the store should still hold the error
    assert ErrorStore().get_errors() == [error]


def test_clear_keeps_recording_on():
    """Test that clearing removes the errors but does not stop recording."""
    # Given an error recorded while recording
    ErrorStore().start_recording()
    ErrorStore().record_error(DataConversionError("bad item"))
    # When clearing the store
    ErrorStore().clear()
    # Then it should be empty
    assert ErrorStore().get_errors() == []
    # And errors recorded afterwards should still be kept
    error = ProviderApiTimeoutError("after clear")
    ErrorStore().record_error(error)
    assert ErrorStore().stop_recording() == [error]


def test_error_recorded_in_another_thread_while_recording_is_kept():
    """Test that the recording flag is shared by the threads of the process."""
    # Given recording started in the main thread
    ErrorStore().start_recording()
    error = DataConversionError("from a worker")
    # When a worker thread records an error
    thread = threading.Thread(target=lambda: ErrorStore().record_error(error))
    thread.start()
    thread.join()
    # Then it should be kept
    assert ErrorStore().stop_recording() == [error]


def test_concurrent_recording_loses_nothing():
    """Test that errors recorded from several threads are all kept, once each."""
    # Given recording on
    ErrorStore().start_recording()
    per_thread = 500

    def record():
        for index in range(per_thread):
            ErrorStore().record_error(DataConversionError(f"item {index}"))

    # When recording errors in several threads at the same time
    _run_in_threads(record)
    # Then every error should be returned, each one once
    errors = ErrorStore().stop_recording()
    assert len(errors) == THREADS * per_thread
    assert len({id(error) for error in errors}) == THREADS * per_thread
