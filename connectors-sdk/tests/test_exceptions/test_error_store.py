"""Offer tests for the store of standardized connector errors."""

import threading

import pytest
from connectors_sdk.exceptions.connector_errors import (
    DataConversionError,
    ProviderApiTimeoutError,
)
from connectors_sdk.exceptions.error_store import ErrorStore

THREADS = 8


@pytest.fixture(autouse=True)
def empty_store():
    """Clear the shared store before and after each test."""
    ErrorStore().clear()
    yield
    ErrorStore().clear()


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
    # Given a recorded error
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


def test_record_error():
    """Test that a handled error is recorded."""
    # Given a handled error
    error = DataConversionError("bad item")
    # When recording it
    ErrorStore().record_error(error)
    # Then it should be returned
    assert ErrorStore().get_errors() == [error]


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(ValueError("x"), id="exception"),
        pytest.param(DataConversionError, id="error_class"),
        pytest.param("data.conversion", id="string"),
    ],
)
def test_record_error_rejects_non_connector_errors(value):
    """Test that recording anything but a ConnectorError fails and records nothing."""
    # Given a store holding one error
    error = DataConversionError("bad item")
    ErrorStore().record_error(error)
    # When recording something that is not a ConnectorError
    # Then a TypeError should be raised
    with pytest.raises(TypeError, match="ConnectorError instances only"):
        ErrorStore().record_error(value)
    # And the store should be unchanged
    assert ErrorStore().get_errors() == [error]


def test_same_error_recorded_twice_is_kept_twice():
    """Test that the store does not deduplicate."""
    # Given an error recorded twice
    error = DataConversionError("bad item")
    ErrorStore().record_error(error)
    ErrorStore().record_error(error)
    # Then it should be returned twice
    assert ErrorStore().get_errors() == [error, error]


def test_get_errors_returns_the_objects_in_recording_order():
    """Test that the recorded objects come back as they are, in order."""
    # Given two recorded errors
    first = DataConversionError("bad item")
    second = ProviderApiTimeoutError("timed out")
    ErrorStore().record_error(first)
    ErrorStore().record_error(second)
    # When reading the errors
    errors = ErrorStore().get_errors()
    # Then they should be the same objects, in recording order
    assert len(errors) == 2
    assert errors[0] is first
    assert errors[1] is second


def test_get_errors_returns_a_copy():
    """Test that changing the returned list does not change the store."""
    # Given a recorded error
    error = DataConversionError("bad item")
    ErrorStore().record_error(error)
    # When clearing the returned list
    ErrorStore().get_errors().clear()
    # Then the store should still hold the error
    assert ErrorStore().get_errors() == [error]


def test_get_errors_on_empty_store():
    """Test that an empty store returns an empty list."""
    # Given nothing recorded
    # Then reading should return an empty list
    assert ErrorStore().get_errors() == []


def test_clear():
    """Test that clearing removes the recorded errors, and recording works after."""
    # Given a recorded error
    ErrorStore().record_error(DataConversionError("previous run"))
    # When clearing the store
    ErrorStore().clear()
    # Then it should be empty
    assert ErrorStore().get_errors() == []
    # And errors recorded afterwards should be returned alone
    error = ProviderApiTimeoutError("this run")
    ErrorStore().record_error(error)
    assert ErrorStore().get_errors() == [error]


def test_concurrent_recording_loses_nothing():
    """Test that errors recorded from several threads are all kept, once each."""
    # Given errors to record from several threads at the same time
    per_thread = 500

    def record():
        for index in range(per_thread):
            ErrorStore().record_error(DataConversionError(f"item {index}"))

    # When recording them concurrently
    _run_in_threads(record)
    # Then every error should be returned, each one once
    errors = ErrorStore().get_errors()
    assert len(errors) == THREADS * per_thread
    assert len({id(error) for error in errors}) == THREADS * per_thread
