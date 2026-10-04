from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import requests
from conftest import NAMESPACE, SPLUNK_URL
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from splunk_hunt.client import SplunkClient, splunk_time

START = datetime(2026, 10, 3, tzinfo=timezone.utc)
END = datetime(2026, 10, 4, tzinfo=timezone.utc)
JOB = f"{NAMESPACE}/search/jobs/sid-1"


def _client(**overrides) -> SplunkClient:
    values = {
        "base_url": SPLUNK_URL,
        "token": "splunk-token",
        "username": None,
        "password": None,
        "verify_ssl": True,
        "app": "search",
        "owner": "nobody",
        "poll_interval": 0.01,
        "logger": MagicMock(),
    }
    values.update(overrides)
    return SplunkClient(**values)


def _status(**content):
    return {"entry": [{"content": content}]}


def test_splunk_time_formats_utc_milliseconds():
    # Given/When/Then times are sent in UTC with milliseconds
    value = datetime(2026, 10, 3, 12, 30, 5, 123456, tzinfo=timezone.utc)
    assert splunk_time(value) == "2026-10-03T12:30:05.123+00:00"


def test_search_runs_a_job_and_reads_paginated_results(requests_mock, monkeypatch):
    # Given a job done after one poll with 3 results, read 2 per page
    monkeypatch.setattr("splunk_hunt.client.RESULTS_PAGE_SIZE", 2)
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(
        JOB,
        [
            {"json": _status(dispatchState="RUNNING", isDone=False)},
            {"json": _status(dispatchState="DONE", isDone=True, resultCount=3)},
        ],
    )
    requests_mock.get(
        f"{NAMESPACE}/search/v2/jobs/sid-1/results",
        [
            {"json": {"results": [{"host": "a"}, {"host": "b"}]}},
            {"json": {"results": [{"host": "c"}, "not-a-row"]}},
        ],
    )
    requests_mock.delete(JOB, json={})
    client = _client()

    # When the search runs
    total, rows = client.search("search x", START, END, 10, RunDeadline(30), "k")

    # Then the job is created over the window, polled, read, and deleted
    create = requests_mock.request_history[0]
    assert create.headers["Authorization"] == "Bearer splunk-token"
    assert "earliest_time=2026-10-03T00%3A00%3A00.000%2B00%3A00" in create.text
    assert "rf=%2A" in create.text
    assert total == 3
    assert rows == [{"host": "a"}, {"host": "b"}, {"host": "c"}]
    assert requests_mock.request_history[-1].method == "DELETE"
    assert client._active_jobs == {}


def test_search_caps_results_and_stops_on_empty_page(requests_mock):
    # Given more results than allowed, and an empty results page
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(JOB, json=_status(isDone=True, resultCount=500))
    requests_mock.get(f"{NAMESPACE}/search/v2/jobs/sid-1/results", json={"results": []})
    requests_mock.delete(JOB, json={})

    # When/Then the total is kept and only the allowed results are requested
    total, rows = _client().search("search x", START, END, 5, RunDeadline(30), "k")
    assert (total, rows) == (500, [])
    results_request = requests_mock.request_history[2]
    assert results_request.qs["count"] == ["5"]


def test_search_uses_basic_authentication(requests_mock):
    # Given a client with credentials
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(JOB, json=_status(isDone=True, resultCount=0))
    requests_mock.delete(JOB, status_code=500)
    client = _client(token=None, username="hunter", password="pw")

    # When/Then basic authentication is used and a failed deletion is only logged
    assert client.search("search x", START, END, 5, RunDeadline(30), "k") == (0, [])
    assert requests_mock.request_history[0].headers["Authorization"] == (
        "Basic aHVudGVyOnB3"
    )
    client._logger.warning.assert_called_once()


def test_search_reports_failed_jobs(requests_mock):
    # Given a failed job
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(
        JOB,
        json=_status(
            dispatchState="FAILED",
            isFailed=True,
            messages=[{"type": "FATAL", "text": "Unknown command"}, {"type": "x"}],
        ),
    )
    requests_mock.delete(JOB, json={})

    # When/Then the Splunk messages are reported
    with pytest.raises(HuntExecutionError, match="Unknown command"):
        _client().search("search x", START, END, 5, RunDeadline(30), "k")


def test_search_reports_failed_jobs_without_message(requests_mock):
    # Given a failed job without message
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(JOB, json=_status(dispatchState="FAILED"))
    requests_mock.delete(JOB, json={})

    # When/Then a generic error is reported
    with pytest.raises(HuntExecutionError, match="no details"):
        _client().search("search x", START, END, 5, RunDeadline(30), "k")


class _FakeClock:
    """Monotonic clock advanced by the deadline sleeps."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_search_times_out_while_polling(requests_mock):
    # Given a job that never completes within a 3 seconds deadline
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(JOB, json={"entry": []})
    requests_mock.delete(JOB, json={})
    clock = _FakeClock()

    # When/Then the run times out and the job is deleted
    with pytest.raises(HuntTimeoutError, match="Splunk search job"):
        _client(poll_interval=1).search(
            "search x",
            START,
            END,
            5,
            RunDeadline(3, clock=clock, sleeper=clock.sleep),
            "k",
        )
    assert clock.now == 3
    assert requests_mock.request_history[-1].method == "DELETE"


def test_search_never_starts_without_time_left(requests_mock):
    # Given an expired deadline
    # When/Then no search job is created
    with pytest.raises(HuntTimeoutError, match="job creation"):
        _client().search("search x", START, END, 5, RunDeadline(0), "k")
    assert requests_mock.call_count == 0


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({"json": {"messages": []}}, id="no_sid"),
        pytest.param({"json": ["unexpected"]}, id="not_object"),
    ],
)
def test_search_requires_a_job_id(requests_mock, response):
    # Given Splunk does not return a job id
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", **response)

    # When/Then the search fails
    with pytest.raises(HuntExecutionError, match="search job id"):
        _client().search("search x", START, END, 5, RunDeadline(30), "k")


def test_search_wraps_http_errors(requests_mock):
    # Given Splunk rejects the search
    requests_mock.post(
        f"{NAMESPACE}/search/v2/jobs",
        status_code=400,
        json={"messages": [{"type": "ERROR", "text": "Error in 'search' command"}]},
    )

    # When/Then the API error is reported with the Splunk message
    with pytest.raises(
        HuntExecutionError, match="job creation failed.*Error in 'search' command"
    ):
        _client().search("search x", START, END, 5, RunDeadline(30), "k")


@pytest.mark.parametrize(
    "error, expected",
    [
        pytest.param(
            requests.exceptions.ConnectTimeout, HuntTimeoutError, id="timeout"
        ),
        pytest.param(
            requests.exceptions.ConnectionError, HuntExecutionError, id="down"
        ),
    ],
)
def test_search_maps_network_errors(requests_mock, error, expected):
    # Given Splunk cannot be reached
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", exc=error)

    # When/Then the network failure is a hunt error
    with pytest.raises(expected):
        _client().search("search x", START, END, 5, RunDeadline(30), "k")


def test_search_deletes_the_job_when_polling_fails(requests_mock):
    # Given a job whose status cannot be read
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(JOB, status_code=503)
    requests_mock.delete(JOB, json={})

    # When/Then the search fails and the job is still deleted
    with pytest.raises(HuntExecutionError, match="job status failed"):
        _client().search("search x", START, END, 5, RunDeadline(30), "k")
    assert requests_mock.request_history[-1].method == "DELETE"


def test_cancel_only_the_job_of_the_run(requests_mock):
    # Given the running jobs of two runs
    requests_mock.post(f"{JOB}/control", json={})
    client = _client(owner="admin user", app="my app")
    client._namespace = "/servicesNS/nobody/search"
    client._active_jobs.update({"run-a": "sid-1", "run-b": "sid-2"})

    # When/Then a run without job cancels nothing, and a run cancels its own job
    client.cancel("run-c")
    assert requests_mock.call_count == 0
    client.cancel("run-a")
    assert requests_mock.call_count == 1
    assert "action=cancel" in requests_mock.last_request.text
    client._logger.info.assert_called_with(
        "[SPLUNK] Search job cancelled", {"sid": "sid-1"}
    )


def test_cancel_logs_failures(requests_mock):
    # Given a job that cannot be cancelled
    requests_mock.post(f"{JOB}/control", status_code=404)
    client = _client()
    client._active_jobs["k"] = "sid-1"

    # When/Then the failure is logged, never raised
    client.cancel("k")
    message, meta = client._logger.warning.call_args.args
    assert "cancellation failed" in message
    assert meta == {"sid": "sid-1"}


def test_namespace_is_url_encoded():
    # Given/When/Then the namespace is URL encoded
    client = _client(owner="admin user", app="my/app")
    assert client._namespace == "/servicesNS/admin%20user/my%2Fapp"
