import pytest
from accenture_connector.run_errors import report_run_errors
from connectors_sdk import (
    Criticity,
    DataConversionError,
    DataNotFoundError,
    ErrorStore,
    ProviderApiAuthenticationError,
    ProviderApiRateLimitError,
)


@pytest.fixture(autouse=True)
def empty_error_store():
    """ErrorStore is a singleton: each test starts and ends with an empty store."""
    ErrorStore().clear()
    yield
    ErrorStore().clear()


def _raise(error: BaseException):
    """Return a run that raises ``error``."""

    def run():
        raise error

    return run


def test_a_successful_run_returns_no_error():
    @report_run_errors
    def run():
        pass

    assert run() == []


def test_the_errors_recorded_during_the_run_are_returned_in_order():
    @report_run_errors
    def run():
        ErrorStore().record_error(DataConversionError("bad image"))
        ErrorStore().record_error(DataNotFoundError("missing image"))

    assert run() == [
        {
            "code": "data.conversion",
            "message": "bad image",
            "criticity": int(Criticity.WARNING),
        },
        {
            "code": "data.not_found",
            "message": "missing image",
            "criticity": int(Criticity.WARNING),
        },
    ]


def test_the_error_that_stopped_the_run_comes_last():
    @report_run_errors
    def run():
        ErrorStore().record_error(DataConversionError("bad image"))
        raise ProviderApiAuthenticationError("bad credentials")

    assert [error["code"] for error in run()] == [
        "data.conversion",
        "api.authentication",
    ]


def test_the_error_that_stopped_the_run_comes_last_when_codes_collide():
    @report_run_errors
    def run():
        ErrorStore().record_error(DataNotFoundError("recorded"))
        raise DataNotFoundError("stopped the run")

    errors = run()

    assert [error["code"] for error in errors] == ["data.not_found", "data.not_found"]
    assert errors[-1]["message"] == "stopped the run"


def test_a_connector_error_keeps_its_code_criticity_and_message():
    run = report_run_errors(_raise(ProviderApiRateLimitError("Too many requests")))

    assert run() == [
        {
            "code": "api.rate_limit",
            "message": "Too many requests",
            "criticity": int(Criticity.ERROR),
        }
    ]


def test_another_exception_is_an_unknown_error_keeping_its_type():
    run = report_run_errors(_raise(KeyError("objects")))

    assert run() == [
        {
            "code": "other.unknown",
            "message": "[KeyError] 'objects'",
            "criticity": int(Criticity.CRITICAL),
        }
    ]


def test_an_exception_without_message_is_reported_with_its_type_alone():
    run = report_run_errors(_raise(TimeoutError()))

    assert run()[0]["message"] == "[TimeoutError]"


@pytest.mark.parametrize("stop", [SystemExit(0), KeyboardInterrupt()])
def test_process_stops_are_not_caught(stop):
    run = report_run_errors(_raise(stop))

    with pytest.raises(type(stop)):
        run()


def test_an_error_recorded_before_the_run_is_not_returned():
    ErrorStore().record_error(DataConversionError("before the run"))

    @report_run_errors
    def run():
        pass

    assert run() == []


def test_the_store_is_empty_after_a_successful_run():
    @report_run_errors
    def run():
        ErrorStore().record_error(DataConversionError("bad image"))

    run()

    assert ErrorStore().get_errors() == []


def test_the_store_is_empty_after_a_failed_run():
    @report_run_errors
    def run():
        ErrorStore().record_error(DataConversionError("bad image"))
        raise RuntimeError("boom")

    run()

    assert ErrorStore().get_errors() == []


def test_the_value_returned_by_the_callback_is_ignored():
    @report_run_errors
    def run():
        return True

    assert run() == []


def test_the_arguments_are_passed_to_the_callback():
    calls = []

    @report_run_errors
    def run(*args, **kwargs):
        calls.append((args, kwargs))

    run(1, key="value")

    assert calls == [((1,), {"key": "value"})]


def test_the_decorated_callback_keeps_its_name_and_wraps_the_original():
    def process_message():
        pass

    run = report_run_errors(process_message)

    assert run.__name__ == "process_message"
    assert run.__wrapped__ is process_message
