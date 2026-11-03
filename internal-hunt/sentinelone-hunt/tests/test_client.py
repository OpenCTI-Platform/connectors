from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from conftest import (
    CONSOLE_URL,
    FORWARD_TAG,
    QUERIES_URL,
    done,
    mock_query,
    running,
)
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from sentinelone_hunt.client import SentinelOneClient, iso_time

START = datetime(2026, 10, 3, tzinfo=timezone.utc)
END = datetime(2026, 10, 4, tzinfo=timezone.utc)


class FakeClock:
    """Clock advanced by the deadline sleeper."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _client(**overrides) -> SentinelOneClient:
    values = {
        "base_url": CONSOLE_URL,
        "api_token": "s1-token",
        "account_ids": [],
        "verify_ssl": True,
        "poll_interval": 1.0,
        "logger": MagicMock(),
    }
    values.update(overrides)
    return SentinelOneClient(**values)


def _deadline(seconds: float, clock: FakeClock) -> RunDeadline:
    return RunDeadline(seconds, clock=clock, sleeper=clock.sleep)


def test_iso_time():
    # Given/When/Then datetimes become ISO 8601 UTC times
    assert iso_time(START) == "2026-10-03T00:00:00Z"
    assert iso_time(START.astimezone(timezone(timedelta(hours=2)))) == (
        "2026-10-03T00:00:00Z"
    )


def test_a_query_answered_at_launch_is_read_and_deleted(requests_mock):
    # Given a small query completed by its launch answer
    delete = mock_query(
        requests_mock, done(["endpoint.name", "event.id"], [["ws1", "e1"]])
    )

    # When it runs
    result = _client().query("event.type = 'x'", START, END, RunDeadline(30), "k")

    # Then the whole tenant is searched over the window with the service user token
    launch = requests_mock.request_history[0]
    assert launch.headers["Authorization"] == "Bearer s1-token"
    assert launch.json() == {
        "queryType": "PQ",
        "startTime": "2026-10-03T00:00:00Z",
        "endTime": "2026-10-04T00:00:00Z",
        "queryPriority": "HIGH",
        "pq": {"query": "event.type = 'x'", "resultType": "TABLE"},
        "tenant": True,
    }
    # And the rows are read, then the query deleted on the node holding it
    assert result.rows == [{"endpoint.name": "ws1", "event.id": "e1"}]
    assert result.match_count == 1
    assert delete.call_count == 1
    assert delete.last_request.headers["X-Dataset-Query-Forward-Tag"] == FORWARD_TAG


def test_accounts_and_the_edr_schema_are_sent_when_set(requests_mock):
    # Given a client restricted to two accounts
    mock_query(requests_mock, done([], []))

    # When a query checked against the EDR schema runs
    _client(account_ids=["111", "222"]).query(
        "q", START, END, RunDeadline(30), "k", edr_schema=True
    )

    # Then only those accounts are searched and the field names are checked
    body = requests_mock.request_history[0].json()
    assert (body["tenant"], body["accountIds"], body["scheme"]) == (
        False,
        ["111", "222"],
        "edr",
    )


def test_a_running_query_is_polled_with_its_forward_tag(requests_mock):
    # Given a query done at the second poll
    clock = FakeClock()
    mock_query(
        requests_mock,
        running(),
        polls=[running(completed=1), done(["a"], [[1]])],
    )

    # When it runs
    result = _client().query("q", START, END, _deadline(30, clock), "k")

    # Then every poll names the last step seen and routes to the node of the query
    polls = [r for r in requests_mock.request_history if r.method == "GET"]
    assert [poll.qs["laststepseen"] for poll in polls] == [["0"], ["1"]]
    assert {poll.headers["X-Dataset-Query-Forward-Tag"] for poll in polls} == {
        FORWARD_TAG
    }
    assert clock.now == 2
    assert result.rows == [{"a": 1}]


def test_polling_stops_at_the_deadline(requests_mock):
    # Given a query that never completes
    clock = FakeClock()
    delete = mock_query(requests_mock, running(), polls=[running()])

    # When/Then the run times out and the query is deleted
    with pytest.raises(HuntTimeoutError):
        _client().query("q", START, END, _deadline(3, clock), "k")
    assert clock.now == 3
    assert delete.call_count == 1


def test_no_request_once_the_deadline_has_expired(requests_mock):
    # Given/When/Then nothing is requested with an expired deadline
    with pytest.raises(HuntTimeoutError):
        _client().query("q", START, END, RunDeadline(0), "k")
    assert requests_mock.call_count == 0


def test_a_throttled_launch_is_retried(requests_mock):
    # Given a launch refused once with HTTP 429
    clock = FakeClock()
    requests_mock.post(
        QUERIES_URL,
        [
            {"status_code": 429, "json": {"message": "Too many requests"}},
            {
                "json": done([], []),
                "headers": {"X-Dataset-Query-Forward-Tag": FORWARD_TAG},
            },
        ],
    )
    requests_mock.delete(f"{QUERIES_URL}/q1", status_code=204)

    # When the query runs
    _client().query("q", START, END, _deadline(30, clock), "k")

    # Then the launch is retried after a backoff
    assert [r.method for r in requests_mock.request_history] == [
        "POST",
        "POST",
        "DELETE",
    ]
    assert clock.now == 1


def test_a_rejected_launch_is_not_retried(requests_mock):
    # Given a launch rejected for an unknown EDR field
    requests_mock.post(
        QUERIES_URL,
        status_code=400,
        json={"message": "Unknown EDR field: 'Endpoint.name'."},
    )

    # When/Then the SentinelOne message is reported after a single launch
    with pytest.raises(HuntExecutionError, match="Unknown EDR field"):
        _client().query("q", START, END, RunDeadline(30), "k")
    assert requests_mock.call_count == 1


def test_a_failed_launch_on_a_server_error_is_not_retried(requests_mock):
    # Given a launch failing with a server error (it may have started a query)
    requests_mock.post(QUERIES_URL, status_code=503, json={})

    # When/Then the launch is not sent twice
    with pytest.raises(HuntExecutionError):
        _client().query("q", START, END, RunDeadline(30), "k")
    assert requests_mock.call_count == 1


def test_a_refused_token_names_what_to_grant(requests_mock):
    # Given a token SentinelOne refuses
    client = _client()
    client.access_denied_hints = {401: "check SENTINELONE_HUNT_API_TOKEN"}
    requests_mock.post(QUERIES_URL, status_code=401, json={"message": "Unauthorized"})

    # When/Then the error tells what to fix
    with pytest.raises(HuntAccessDeniedError, match="SENTINELONE_HUNT_API_TOKEN"):
        client.query("q", START, END, RunDeadline(30), "k")


@pytest.mark.parametrize(
    "answer, headers, message",
    [
        pytest.param({}, {"X-Dataset-Query-Forward-Tag": "t"}, "query id", id="no_id"),
        pytest.param(
            ["x"], {"X-Dataset-Query-Forward-Tag": "t"}, "query id", id="list"
        ),
        pytest.param({"id": "q1"}, {}, "Forward-Tag", id="no_forward_tag"),
    ],
)
def test_incomplete_launch_answers_fail(requests_mock, answer, headers, message):
    # Given a launch answer without query id or forward tag
    requests_mock.post(QUERIES_URL, json=answer, headers=headers)

    # When/Then the query fails with what is missing
    with pytest.raises(HuntExecutionError, match=message):
        _client().query("q", START, END, RunDeadline(30), "k")


def test_an_unexpected_status_answer_fails_and_deletes_the_query(requests_mock):
    # Given a status answer that is not an object
    delete = mock_query(requests_mock, running(), polls=[["x"]])

    # When/Then the query fails and is still deleted
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        _client().query("q", START, END, _deadline(30, FakeClock()), "k")
    assert delete.call_count == 1


@pytest.mark.parametrize(
    "answer, rows, match_count",
    [
        pytest.param(
            {
                "stepsCompleted": 1,
                "stepsTotal": 1,
                "data": {"columns": ["a", "b"], "values": [[1, 2]]},
            },
            [{"a": 1, "b": 2}],
            None,
            id="string_columns",
        ),
        pytest.param(
            {
                "stepsCompleted": 1,
                "stepsTotal": 1,
                "matchCount": 5,
                "data": {"values": [[1], "bad"]},
            },
            [{}],
            5,
            id="no_columns_top_level_count",
        ),
        pytest.param(
            {"stepsCompleted": "1", "stepsTotal": "1", "data": None},
            [],
            None,
            id="no_data",
        ),
        pytest.param(
            {"stepsCompleted": 1, "stepsTotal": 1, "data": {"matchCount": True}},
            [],
            None,
            id="boolean_count",
        ),
    ],
)
def test_result_shapes(requests_mock, answer, rows, match_count):
    # Given completed answers of various shapes
    mock_query(requests_mock, {"id": "q1", **answer})

    # When the query runs
    result = _client().query("q", START, END, RunDeadline(30), "k")

    # Then the rows and the match count are read when present
    assert (result.rows, result.match_count) == (rows, match_count)


def test_invalid_step_counters_keep_polling(requests_mock):
    # Given answers with invalid step counters, then a completed one
    clock = FakeClock()
    mock_query(
        requests_mock,
        {"id": "q1", "stepsCompleted": True, "stepsTotal": "n/a"},
        polls=[done([], [])],
    )

    # When/Then the query is polled until it completes
    _client().query("q", START, END, _deadline(30, clock), "k")
    assert requests_mock.request_history[1].qs["laststepseen"] == ["0"]


def test_cancel_deletes_only_the_query_of_the_run(requests_mock):
    # Given a query running for a run
    client = _client()
    requests_mock.post(
        QUERIES_URL,
        json=running(),
        headers={"X-Dataset-Query-Forward-Tag": FORWARD_TAG},
    )
    delete = requests_mock.delete(f"{QUERIES_URL}/q1", status_code=204)

    def _poll(request, context):
        client.cancel("other-run")
        client.cancel("k")
        return done([], [])

    requests_mock.get(f"{QUERIES_URL}/q1", json=_poll)

    # When the run is cancelled while polling
    client.query("q", START, END, _deadline(30, FakeClock()), "k")

    # Then the query is deleted once, by the cancellation
    assert delete.call_count == 1


def test_failed_deletion_is_logged(requests_mock):
    # Given a query that cannot be deleted
    logger = MagicMock()
    requests_mock.post(
        QUERIES_URL,
        json=done([], [], query_id="q/1"),
        headers={"X-Dataset-Query-Forward-Tag": FORWARD_TAG},
    )
    requests_mock.delete(f"{QUERIES_URL}/q%2F1", status_code=404, json={})

    # When the query completes
    _client(logger=logger).query("q", START, END, RunDeadline(30), "k")

    # Then the cleanup failure is logged as a warning
    message, details = logger.warning.call_args.args
    assert "The PowerQuery deletion failed" in message
    assert details == {"query": "/sdl/v2/api/queries/q%2F1"}
