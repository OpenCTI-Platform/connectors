from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import parse_qs

import pytest
from conftest import GRAPH_URL, HUNTING_URL, LOGIN_URL, TOKEN_URL, answer
from connectors_sdk.connectors.internal_hunt import (
    HuntAccessDeniedError,
    HuntExecutionError,
    HuntQueryRejectedError,
    RunDeadline,
)
from microsoft_defender_hunt.client import (
    CallRateLimiter,
    DefenderHuntingClient,
    EntraTokenClient,
    iso_time,
    timespan,
)


class FakeClock:
    """Monotonic clock advanced by the sleeps of the code under test."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _deadline(clock: FakeClock, seconds: float = 30.0) -> RunDeadline:
    return RunDeadline(seconds, clock=clock, sleeper=clock.sleep)


def _tokens(clock: FakeClock | None = None) -> EntraTokenClient:
    kwargs = {"clock": clock} if clock else {}
    return EntraTokenClient(
        login_url=LOGIN_URL,
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="secret-1",
        scope=f"{GRAPH_URL}/.default",
        **kwargs,
    )


def _client(clock: FakeClock | None = None) -> DefenderHuntingClient:
    limiter = CallRateLimiter(clock=clock) if clock else None
    client = DefenderHuntingClient(
        GRAPH_URL, _tokens(clock), frozenset({"AdditionalFields"}), limiter
    )
    client.access_denied_hints = {403: "grant ThreatHunting.Read.All"}
    return client


def test_times_are_formatted_for_the_timespan():
    # Given a window with microseconds and a non-UTC offset
    start = datetime(2026, 10, 3, 2, 0, 0, 123456, tzinfo=timezone(timedelta(hours=2)))
    end = datetime(2026, 10, 4, tzinfo=UTC)

    # When/Then each bound is an ISO 8601 UTC time with milliseconds
    assert iso_time(start) == "2026-10-03T00:00:00.123Z"
    assert timespan(start, end) == "2026-10-03T00:00:00.123Z/2026-10-04T00:00:00.000Z"


def test_rate_limiter_spaces_the_calls_beyond_the_burst():
    # Given a quota of 45 calls per minute
    clock = FakeClock()
    limiter = CallRateLimiter(limits=((45, 60.0),), clock=clock)
    deadline = _deadline(clock, 600)

    # When 46 calls are sent at once
    for _ in range(46):
        limiter.acquire(deadline)

    # Then the burst goes through, and the 46th call waits for one token
    assert clock.sleeps == [pytest.approx(60 / 45)]


def test_rate_limiter_honours_every_quota():
    # Given a burst of 5 calls per second and 4 calls per hour
    clock = FakeClock()
    limiter = CallRateLimiter(limits=((5, 1.0), (4, 3600.0)), clock=clock)
    deadline = _deadline(clock, 7200)

    # When 5 calls are sent
    for _ in range(5):
        limiter.acquire(deadline)

    # Then the fifth one waits for the hourly quota
    assert clock.sleeps == [pytest.approx(900.0)]


def test_rate_limiter_fails_when_no_call_fits_before_the_deadline():
    # Given an exhausted quota and a short deadline
    clock = FakeClock()
    limiter = CallRateLimiter(limits=((1, 60.0),), clock=clock)
    deadline = _deadline(clock, 10)
    limiter.acquire(deadline)

    # When/Then the next call is refused without waiting
    with pytest.raises(HuntExecutionError, match="1 per 60 seconds"):
        limiter.acquire(deadline)
    assert clock.sleeps == []


def test_token_is_requested_with_the_client_credentials_and_cached(requests_mock):
    # Given Microsoft Entra ID issuing a one-hour token
    entra = requests_mock.post(
        TOKEN_URL, json={"access_token": "graph-1", "expires_in": 3600}
    )
    clock = FakeClock()
    tokens = _tokens(clock)

    # When a token is needed twice within its lifetime
    first = tokens.access_token(_deadline(clock))
    second = tokens.access_token(_deadline(clock))

    # Then one client credentials request is sent for the Graph scope
    assert (first, second) == ("graph-1", "graph-1")
    assert entra.call_count == 1
    form = parse_qs(entra.last_request.text)
    assert form == {
        "grant_type": ["client_credentials"],
        "client_id": ["client-1"],
        "client_secret": ["secret-1"],
        "scope": [f"{GRAPH_URL}/.default"],
    }


def test_token_is_renewed_before_it_expires(requests_mock):
    # Given a token expiring in one hour
    entra = requests_mock.post(
        TOKEN_URL,
        [
            {"json": {"access_token": "graph-1", "expires_in": 3600}},
            {"json": {"access_token": "graph-2", "expires_in": 3600}},
        ],
    )
    clock = FakeClock()
    tokens = _tokens(clock)
    tokens.access_token(_deadline(clock))

    # When it is needed again within the refresh margin
    clock.now += 3600 - 60

    # Then a new token is requested
    assert tokens.access_token(_deadline(clock)) == "graph-2"
    assert entra.call_count == 2


@pytest.mark.parametrize("status", [400, 401])
def test_refused_credentials_name_the_settings_to_check(requests_mock, status):
    # Given Microsoft Entra ID refusing the client secret
    requests_mock.post(
        TOKEN_URL,
        status_code=status,
        json={
            "error": "invalid_client",
            "error_description": "AADSTS7000215: Invalid client secret provided.",
        },
    )

    # When/Then the error names the settings and the answer, never the secret
    with pytest.raises(HuntAccessDeniedError) as err:
        _tokens().access_token(RunDeadline(30))
    message = str(err.value)
    assert "MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET" in message
    assert "AADSTS7000215" in message
    assert "secret-1" not in message


def test_a_token_answer_without_token_fails(requests_mock):
    # Given Microsoft Entra ID answering without a token
    requests_mock.post(TOKEN_URL, json={"token_type": "Bearer"})

    # When/Then the authentication fails
    with pytest.raises(HuntExecutionError, match="no access token"):
        _tokens().access_token(RunDeadline(30))


def test_run_query_sends_the_query_with_a_token_and_reads_the_rows(
    requests_mock, entra
):
    # Given advanced hunting answering with a dynamic and a raw column
    requests_mock.post(
        HUNTING_URL,
        json=answer(
            [
                ("Timestamp", "DateTime"),
                ("DeviceName", "String"),
                ("Extra", "Dynamic"),
                ("AdditionalFields", "Dynamic"),
                ("Plain", "Dynamic"),
            ],
            [
                [
                    "2026-10-03T10:00:00.1234567Z",
                    "ws1",
                    '{"a": 1}',
                    '{"raw": true}',
                    "not json",
                ]
            ],
        ),
    )

    # When a query runs
    result = _client().run_query("DeviceInfo | take 1", "P7D", RunDeadline(30))

    # Then it is sent with its timespan and a bearer token
    request = requests_mock.last_request
    assert request.json() == {"Query": "DeviceInfo | take 1", "Timespan": "P7D"}
    assert request.headers["Authorization"] == "Bearer graph-1"
    # And the rows are read by schema name, dynamic columns decoded except raw ones
    assert result.columns == (
        "Timestamp",
        "DeviceName",
        "Extra",
        "AdditionalFields",
        "Plain",
    )
    assert result.rows == [
        {
            "Timestamp": "2026-10-03T10:00:00.1234567Z",
            "DeviceName": "ws1",
            "Extra": {"a": 1},
            "AdditionalFields": '{"raw": true}',
            "Plain": "not json",
        }
    ]


def test_run_query_reads_capitalised_answers(requests_mock, entra):
    # Given an answer with capitalised property names
    requests_mock.post(
        HUNTING_URL,
        json={
            "Schema": [{"Name": "DeviceName", "Type": "String"}],
            "Results": [{"devicename": "ws1"}, "ignored"],
        },
    )

    # When/Then the rows are keyed by the schema names
    rows = _client().run_query("T", "P1D", RunDeadline(30)).rows
    assert rows == [{"DeviceName": "ws1"}]


def test_one_token_serves_several_queries(requests_mock, entra):
    # Given advanced hunting answering every query
    requests_mock.post(HUNTING_URL, json=answer([("x", "Int32")], []))
    client = _client()

    # When two queries run
    client.run_query("A", "P1D", RunDeadline(30))
    client.run_query("B", "P1D", RunDeadline(30))

    # Then Microsoft Entra ID is asked once
    assert entra.call_count == 1


def test_a_throttled_query_is_sent_again_after_retry_after(requests_mock, entra):
    # Given advanced hunting throttling the first query
    hunting = requests_mock.post(
        HUNTING_URL,
        [
            {
                "status_code": 429,
                "headers": {"Retry-After": "7"},
                "json": {"error": {"code": "TooManyRequests", "message": "Slow down"}},
            },
            {"json": answer([("DeviceName", "String")], [["ws1"]])},
        ],
    )
    clock = FakeClock()
    client = _client(clock)

    # When the query runs
    rows = client.run_query("T", "P1D", _deadline(clock, 60)).rows

    # Then it is sent again after the delay advanced hunting asked for
    assert rows == [{"DeviceName": "ws1"}]
    assert hunting.call_count == 2
    assert clock.sleeps == [7.0]


def test_a_throttled_query_fails_when_the_delay_outlives_the_run(requests_mock, entra):
    # Given advanced hunting throttling the query for longer than the run
    requests_mock.post(
        HUNTING_URL,
        status_code=429,
        headers={"Retry-After": "120"},
        json={"error": {"code": "TooManyRequests", "message": "Quota exceeded"}},
    )
    clock = FakeClock()

    # When/Then the run fails with the answer of advanced hunting, without waiting
    with pytest.raises(HuntExecutionError, match="Quota exceeded"):
        _client(clock).run_query("T", "P1D", _deadline(clock, 60))
    assert clock.sleeps == []


def test_a_missing_permission_names_it(requests_mock, entra):
    # Given an app registration without ThreatHunting.Read.All
    requests_mock.post(
        HUNTING_URL,
        status_code=403,
        json={"error": {"code": "Forbidden", "message": "Missing role permissions"}},
    )

    # When/Then the error names the permission to grant
    with pytest.raises(HuntAccessDeniedError) as err:
        _client().run_query("T", "P1D", RunDeadline(30))
    assert "grant ThreatHunting.Read.All" in str(err.value)
    assert "Missing role permissions" in str(err.value)


def test_a_rejected_query_is_not_retried(requests_mock, entra):
    # Given advanced hunting rejecting the syntax of a query
    hunting = requests_mock.post(
        HUNTING_URL,
        status_code=400,
        json={"error": {"code": "BadRequest", "message": "Query could not be parsed"}},
    )

    # When/Then the query is rejected once, with the reason
    with pytest.raises(HuntQueryRejectedError, match="could not be parsed"):
        _client().run_query("T |", "P1D", RunDeadline(30))
    assert hunting.call_count == 1


def test_an_unexpected_answer_fails(requests_mock, entra):
    # Given advanced hunting answering with a list
    requests_mock.post(HUNTING_URL, json=[1, 2])

    # When/Then the query fails
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        _client().run_query("T", "P1D", RunDeadline(30))
