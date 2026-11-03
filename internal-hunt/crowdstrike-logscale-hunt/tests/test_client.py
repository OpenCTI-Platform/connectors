from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from conftest import API_URL, JOBS_URL, TOKEN_URL, done, mock_falcon_job
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from crowdstrike_logscale_hunt.client import LogScaleClient, epoch_ms

START = datetime(2026, 10, 3, tzinfo=timezone.utc)
END = datetime(2026, 10, 4, tzinfo=timezone.utc)
LOGSCALE_URL = "https://logscale.example.com"
LOGSCALE_JOBS = f"{LOGSCALE_URL}/api/v1/repositories/win%20logs/queryjobs"


class FakeClock:
    """Clock advanced by the deadline sleeper."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _falcon(**overrides) -> LogScaleClient:
    values = {
        "base_url": API_URL,
        "path_prefix": "/humio",
        "repository": "search-all",
        "verify_ssl": True,
        "poll_interval": 1.0,
        "logger": MagicMock(),
        "client_id": "client-1",
        "client_secret": "secret-1",
    }
    values.update(overrides)
    return LogScaleClient(**values)


def test_epoch_ms():
    # Given/When/Then datetimes become epoch milliseconds
    assert epoch_ms(START) == 1790985600000


def test_falcon_query_authenticates_runs_and_deletes_the_job(requests_mock):
    # Given a Falcon query job completing at the first poll
    delete = mock_falcon_job(requests_mock, [done([{"ComputerName": "ws1"}])])

    # When the query runs
    result = _falcon().query("x=1", START, END, RunDeadline(30), "k")

    # Then the client authenticates, creates the job over the window and deletes it
    token, create = requests_mock.request_history[:2]
    assert "client_id=client-1" in token.text and "client_secret=secret-1" in token.text
    assert "Authorization" not in token.headers
    assert create.headers["Authorization"] == "Bearer tok"
    assert create.json() == {
        "queryString": "x=1",
        "start": 1790985600000,
        "end": 1791072000000,
        "isLive": False,
    }
    assert result.events == [{"ComputerName": "ws1"}]
    assert result.warnings == []
    assert delete.call_count == 1


def test_the_token_is_reused_until_it_expires(requests_mock):
    # Given a client with a fake clock
    clock = FakeClock()
    client = _falcon(clock=clock)
    mock_falcon_job(requests_mock, [done([]), done([]), done([])])
    token = requests_mock.post(
        TOKEN_URL, json={"access_token": "tok", "expires_in": 120}
    )

    # When queries run before and after the token expiry
    client.query("q", START, END, RunDeadline(30), "k")
    client.query("q", START, END, RunDeadline(30), "k")
    clock.now = 61
    client.query("q", START, END, RunDeadline(30), "k")

    # Then the token is requested again only once expired
    assert token.call_count == 2


def test_the_token_lifetime_defaults_when_missing(requests_mock):
    # Given a token answer without lifetime
    clock = FakeClock()
    client = _falcon(clock=clock)
    mock_falcon_job(requests_mock, [done([]), done([])])
    token = requests_mock.post(TOKEN_URL, json={"access_token": "tok"})

    # When/Then the token is kept for the default lifetime
    client.query("q", START, END, RunDeadline(30), "k")
    clock.now = 1000
    client.query("q", START, END, RunDeadline(30), "k")
    assert token.call_count == 1


def test_authentication_failures_are_reported(requests_mock):
    # Given rejected API credentials
    requests_mock.post(
        TOKEN_URL, status_code=403, json={"errors": [{"message": "access denied"}]}
    )

    # When/Then the error carries the CrowdStrike message
    with pytest.raises(HuntExecutionError, match="access denied"):
        _falcon().query("q", START, END, RunDeadline(30), "k")


def test_a_token_answer_without_token_fails(requests_mock):
    # Given an answer without access token
    requests_mock.post(TOKEN_URL, json={"errors": []})

    # When/Then the query fails
    with pytest.raises(HuntExecutionError, match="access token"):
        _falcon().query("q", START, END, RunDeadline(30), "k")


def test_logscale_clusters_use_the_api_token(requests_mock):
    # Given a LogScale cluster client
    client = LogScaleClient(
        base_url=LOGSCALE_URL,
        path_prefix="",
        repository="win logs",
        verify_ssl=False,
        poll_interval=1.0,
        logger=MagicMock(),
        api_token="ls-token",
    )
    requests_mock.post(LOGSCALE_JOBS, json={"id": "j/1"})
    requests_mock.get(f"{LOGSCALE_JOBS}/j%2F1", json=done([]))
    requests_mock.delete(f"{LOGSCALE_JOBS}/j%2F1", status_code=204)

    # When the query runs
    client.query("q", START, END, RunDeadline(30), "k")

    # Then the API token is used and no OAuth2 token is requested
    assert all(
        request.headers["Authorization"] == "Bearer ls-token"
        for request in requests_mock.request_history
    )
    assert requests_mock.request_history[0].verify is False


def test_polling_follows_the_logscale_hint(requests_mock):
    # Given a job done at the third poll, with and without poll hints
    clock = FakeClock()
    mock_falcon_job(
        requests_mock,
        [
            {"done": False, "metaData": {"pollAfter": 250}},
            {"done": False, "metaData": {}},
            done([{"a": 1}], warnings=[{"message": "partial"}, "other"]),
        ],
    )

    # When the query runs
    result = _falcon().query(
        "q", START, END, RunDeadline(30, clock=clock, sleeper=clock.sleep), "k"
    )

    # Then it waited for the hint, then for the poll interval
    assert clock.now == pytest.approx(1.25)
    assert result.warnings == ["partial", "other"]


def test_polling_stops_at_the_deadline(requests_mock):
    # Given a job that never completes
    clock = FakeClock()
    requests_mock.post(TOKEN_URL, json={"access_token": "tok"})
    requests_mock.post(JOBS_URL, json={"id": "j1"})
    requests_mock.get(f"{JOBS_URL}/j1", json={"done": False, "metaData": {}})
    delete = requests_mock.delete(f"{JOBS_URL}/j1", status_code=204)

    # When/Then the run times out and the job is deleted
    with pytest.raises(HuntTimeoutError):
        _falcon().query(
            "q", START, END, RunDeadline(3, clock=clock, sleeper=clock.sleep), "k"
        )
    assert clock.now == 3
    assert delete.call_count == 1


def test_no_request_once_the_deadline_has_expired(requests_mock):
    # Given/When/Then nothing is requested with an expired deadline
    with pytest.raises(HuntTimeoutError):
        _falcon().query("q", START, END, RunDeadline(0), "k")
    assert requests_mock.call_count == 0


@pytest.mark.parametrize(
    "answer, message",
    [
        pytest.param({"done": True, "cancelled": True}, "cancelled", id="cancelled"),
        pytest.param(["x"], "unexpected answer", id="not_an_object"),
    ],
)
def test_failed_jobs(requests_mock, answer, message):
    # Given a job cancelled by LogScale or an unexpected answer
    delete = mock_falcon_job(requests_mock, [answer])

    # When/Then the query fails and the job is still deleted
    with pytest.raises(HuntExecutionError, match=message):
        _falcon().query("q", START, END, RunDeadline(30), "k")
    assert delete.call_count == 1


def test_job_creation_errors_are_reported(requests_mock):
    # Given an invalid query
    requests_mock.post(TOKEN_URL, json={"access_token": "tok"})
    requests_mock.post(
        JOBS_URL, status_code=400, text="Unknown function: foo", headers={}
    )

    # When/Then the LogScale message is reported
    with pytest.raises(HuntExecutionError, match="Unknown function"):
        _falcon().query("foo()", START, END, RunDeadline(30), "k")


def test_job_creation_without_id(requests_mock):
    # Given a creation answer without job id
    requests_mock.post(TOKEN_URL, json={"access_token": "tok"})
    requests_mock.post(JOBS_URL, json={})

    # When/Then the query fails
    with pytest.raises(HuntExecutionError, match="query job id"):
        _falcon().query("q", START, END, RunDeadline(30), "k")


def test_cancel_deletes_only_the_job_of_the_run(requests_mock):
    # Given a job running for a run
    client = _falcon()
    requests_mock.post(TOKEN_URL, json={"access_token": "tok"})
    requests_mock.post(JOBS_URL, json={"id": "j1"})
    delete = requests_mock.delete(f"{JOBS_URL}/j1", status_code=204)

    def _poll(request, context):
        client.cancel("other-run")
        client.cancel("k")
        return done([])

    requests_mock.get(f"{JOBS_URL}/j1", json=_poll)

    # When the run is cancelled while polling
    client.query("q", START, END, RunDeadline(30), "k")

    # Then the job is deleted once, by the cancellation
    assert delete.call_count == 1


def test_failed_deletion_is_logged(requests_mock):
    # Given a job that cannot be deleted
    logger = MagicMock()
    mock_falcon_job(requests_mock, [done([])])
    requests_mock.delete(f"{JOBS_URL}/j1", status_code=404, json={})

    # When the query completes
    _falcon(logger=logger).query("q", START, END, RunDeadline(30), "k")

    # Then the cleanup failure is logged as a warning
    message, details = logger.warning.call_args.args
    assert "The LogScale query job deletion failed" in message
    assert details == {"job": "/humio/api/v1/repositories/search-all/queryjobs/j1"}
