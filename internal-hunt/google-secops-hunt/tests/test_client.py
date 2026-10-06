from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from conftest import RUN_RULE_URL, UDM_SEARCH_URL, FakeCredentials, udm_event
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from google.auth.exceptions import RefreshError, TransportError
from google_secops_hunt.client import (
    MAX_RESULTS,
    SecOpsClient,
    _BoundedAuthRequest,
    rfc3339,
)

START = datetime(2026, 10, 3, tzinfo=timezone.utc)
END = datetime(2026, 10, 4, tzinfo=timezone.utc)


def make_client(credentials: FakeCredentials | None = None) -> SecOpsClient:
    return SecOpsClient(
        base_url="https://chronicle.googleapis.com/",
        project_id="hunt-project",
        region="europe",
        instance="instance-1",
        credentials=credentials or FakeCredentials(),
    )


def query_params(request) -> dict[str, str]:
    return {
        key: values[0] for key, values in parse_qs(urlparse(request.url).query).items()
    }


def test_rfc3339_formats_utc_milliseconds():
    # Given/When/Then a time of another time zone is formatted in UTC with milliseconds
    value = datetime(
        2026, 10, 3, 12, 30, 1, 123456, tzinfo=timezone(timedelta(hours=2))
    )
    assert rfc3339(value) == "2026-10-03T10:30:01.123Z"


def test_udm_search_calls_the_regional_endpoint(requests_mock):
    # Given a UDM search answer with more data available
    requests_mock.get(
        UDM_SEARCH_URL,
        json={
            "events": [udm_event("2026-10-03T10:00:00Z"), {"plain": 1}, "noise"],
            "moreDataAvailable": True,
        },
    )
    credentials = FakeCredentials()

    # When a search runs
    result = make_client(credentials).udm_search(
        'metadata.event_type = "PROCESS_LAUNCH"', START, END, 50, RunDeadline(120)
    )

    # Then the regional host is called with the window, the limit and the token
    request = requests_mock.last_request
    assert query_params(request) == {
        "query": 'metadata.event_type = "PROCESS_LAUNCH"',
        "timeRange.startTime": "2026-10-03T00:00:00.000Z",
        "timeRange.endTime": "2026-10-04T00:00:00.000Z",
        "limit": "50",
    }
    assert request.headers["Authorization"] == "Bearer token-1"
    # And the UDM documents are returned, the result being truncated
    assert result.events == [
        {
            "metadata": {
                "event_timestamp": "2026-10-03T10:00:00Z",
                "id": "abc-2026-10-03T10:00:00Z",
            }
        },
        {"plain": 1},
    ]
    assert (result.detections, result.truncated) == (None, True)
    # And the token was requested with a bounded timeout
    assert isinstance(credentials.requests[0], _BoundedAuthRequest)
    assert credentials.requests[0]._timeout == 30


def test_udm_search_caps_the_limit(requests_mock):
    # Given an empty answer
    requests_mock.get(UDM_SEARCH_URL, json={})

    # When a search asks for more than the API returns
    result = make_client().udm_search("x", START, END, 50000, RunDeadline(30))

    # Then the limit is capped and nothing is truncated
    assert query_params(requests_mock.last_request)["limit"] == str(MAX_RESULTS)
    assert (result.events, result.truncated) == ([], False)


def test_udm_search_rejects_unexpected_answers(requests_mock):
    # Given/When/Then an answer that is not an object is rejected
    requests_mock.get(UDM_SEARCH_URL, json=["unexpected"])
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        make_client().udm_search("x", START, END, 10, RunDeadline(30))


def test_udm_search_maps_api_errors(requests_mock):
    # Given a service account without the Chronicle permission
    requests_mock.get(
        UDM_SEARCH_URL,
        status_code=403,
        json={"error": {"code": 403, "message": "Permission denied"}},
    )

    # When/Then the search fails with the reason
    with pytest.raises(HuntExecutionError, match="Permission denied"):
        make_client().udm_search("x", START, END, 10, RunDeadline(30))


def test_udm_search_maps_timeouts(requests_mock):
    # Given/When/Then a request timeout becomes a hunt timeout
    requests_mock.get(UDM_SEARCH_URL, exc=requests.ConnectTimeout)
    with pytest.raises(HuntTimeoutError):
        make_client().udm_search("x", START, END, 10, RunDeadline(30))


def test_valid_tokens_are_reused(requests_mock):
    # Given valid credentials
    requests_mock.get(UDM_SEARCH_URL, json={})
    credentials = FakeCredentials(valid=True)
    client = make_client(credentials)

    # When two searches run
    client.udm_search("x", START, END, 10, RunDeadline(30))
    client.udm_search("y", START, END, 10, RunDeadline(30))

    # Then the token is never refreshed
    assert credentials.requests == []
    assert requests_mock.last_request.headers["Authorization"] == "Bearer token-0"


def test_authentication_failures_are_reported(requests_mock):
    # Given credentials Google refuses
    credentials = FakeCredentials(error=RefreshError("invalid_grant: bad key"))

    # When/Then the search fails before calling SecOps
    with pytest.raises(
        HuntExecutionError, match="authentication failed.*invalid_grant"
    ):
        make_client(credentials).udm_search("x", START, END, 10, RunDeadline(30))
    assert requests_mock.call_count == 0


def test_a_token_refresh_outliving_the_deadline_is_a_timeout(requests_mock):
    # Given a token refresh using up the run budget, reported by google-auth
    # as an authentication error
    now = [0.0]
    deadline = RunDeadline(10, clock=lambda: now[0])

    class StalledCredentials(FakeCredentials):
        def refresh(self, request):
            self.requests.append(request)
            now[0] = 11.0
            raise TransportError("HTTPSConnectionPool: Read timed out.")

    credentials = StalledCredentials()

    # When/Then the run is reported as timed out, not failed, before calling SecOps
    with pytest.raises(
        HuntTimeoutError, match="Google authentication did not complete"
    ):
        make_client(credentials).udm_search("x", START, END, 10, deadline)
    assert requests_mock.call_count == 0


def test_a_transport_error_within_the_deadline_is_a_failure(requests_mock):
    # Given/When/Then a refresh failing while time is left is an auth failure
    credentials = FakeCredentials(error=TransportError("connection refused"))
    with pytest.raises(
        HuntExecutionError, match="authentication failed.*connection refused"
    ):
        make_client(credentials).udm_search("x", START, END, 10, RunDeadline(30))
    assert requests_mock.call_count == 0


def test_authentication_respects_the_deadline():
    # Given an expired deadline
    now = [0.0]
    deadline = RunDeadline(1, clock=lambda: now[0])
    now[0] = 5.0

    # When/Then the token is not requested
    credentials = FakeCredentials()
    with pytest.raises(HuntTimeoutError, match="Google authentication"):
        make_client(credentials).udm_search("x", START, END, 10, deadline)
    assert credentials.requests == []


def test_authentication_never_waits_longer_than_the_time_left(requests_mock):
    # Given a deadline with half a second left
    requests_mock.get(UDM_SEARCH_URL, json={})
    now = [0.0]
    deadline = RunDeadline(10, clock=lambda: now[0])
    now[0] = 9.5
    credentials = FakeCredentials()

    # When a search runs
    make_client(credentials).udm_search("x", START, END, 10, deadline)

    # Then the token request is bounded by the time left
    assert credentials.requests[0]._timeout == pytest.approx(0.5)


def test_bounded_auth_request_forces_the_timeout():
    # Given a bounded transport
    with patch("google_secops_hunt.client.GoogleAuthRequest") as request_cls:
        request = _BoundedAuthRequest(7)

        # When google-auth sends a token request with its own timeout
        request("https://oauth2.googleapis.com/token", method="POST", timeout=120)

    # Then the run deadline bound applies
    request_cls.return_value.assert_called_once_with(
        "https://oauth2.googleapis.com/token", method="POST", timeout=7
    )


def test_run_rule_collects_detection_events(requests_mock):
    # Given a rule test streaming progress, two detections and a cap notice
    event = {"metadata": {"event_timestamp": "2026-10-03T10:00:00Z"}}
    requests_mock.post(
        RUN_RULE_URL,
        json=[
            {"progressPercent": 50},
            {
                "detection": {
                    "id": "de_7f3e0c1a",
                    "detectionTime": "2026-10-03T10:00:01Z",
                    "collectionElements": [
                        {"references": [{"event": event}, "noise", {"entity": {}}]}
                    ],
                }
            },
            {"detection": {"detectionTime": "2026-10-03T11:00:00Z"}},
            "noise",
            {"tooManyDetections": True},
        ],
    )

    # When the rule runs
    result = make_client().run_rule("rule x {}", START, END, 10, RunDeadline(30))

    # Then the rule, the window and the cap are sent
    assert requests_mock.last_request.json() == {
        "ruleText": "rule x {}",
        "timeRange": {
            "startTime": "2026-10-03T00:00:00.000Z",
            "endTime": "2026-10-04T00:00:00.000Z",
        },
        "maxResults": 10,
        "scope": "",
    }
    # And the events of the detections are returned, the result being truncated
    assert result.events == [event, {"detectionTime": "2026-10-03T11:00:00Z"}]
    # Each detection is labelled by its id, else by a digest of its content: the
    # same label at every run that finds it, whatever its position in the answer
    first, second = result.event_detections
    assert first == "de_7f3e0c1a"
    assert second.startswith("detection-") and len(second) == len("detection-") + 32
    again = make_client().run_rule("rule x {}", START, END, 10, RunDeadline(30))
    assert again.event_detections == result.event_detections
    assert (result.detections, result.truncated) == (2, True)


def test_run_rule_keeps_the_events_within_the_run_budget(requests_mock):
    # Given two detections naming three events each, more than the four events of the run
    def detection(name):
        events = [
            {"event": {"metadata": {"id": f"{name}-{step}"}}} for step in range(3)
        ]
        return {
            "detection": {"id": name, "collectionElements": [{"references": events}]}
        }

    requests_mock.post(RUN_RULE_URL, json=[detection("de_1"), detection("de_2")])

    # When the rule runs with a budget of four events
    result = make_client().run_rule("rule x {}", START, END, 4, RunDeadline(30))

    # Then the events beyond the budget are left out and the result is partial
    assert [event["metadata"]["id"] for event in result.events] == [
        "de_1-0",
        "de_1-1",
        "de_1-2",
        "de_2-0",
    ]
    assert result.event_detections == ["de_1"] * 3 + ["de_2"]
    assert (result.detections, result.truncated) == (2, True)


def test_run_rule_accepts_a_single_object(requests_mock):
    # Given an answer holding a single progress object
    requests_mock.post(RUN_RULE_URL, json={"progressPercent": 100})

    # When/Then the rule has no detection
    result = make_client().run_rule("rule x {}", START, END, 20000, RunDeadline(30))
    assert requests_mock.last_request.json()["maxResults"] == MAX_RESULTS
    assert (result.events, result.detections, result.truncated) == ([], 0, False)
    assert result.event_detections == []


@pytest.mark.parametrize(
    "item, message",
    [
        pytest.param(
            {"ruleCompilationError": {"message": "unknown field udm.foo"}},
            "does not compile: unknown field udm.foo",
            id="compilation",
        ),
        pytest.param(
            {"ruleError": {"message": "quota exceeded"}},
            "rule failed: quota exceeded",
            id="rule_error",
        ),
    ],
)
def test_run_rule_reports_rule_errors(requests_mock, item, message):
    # Given/When/Then a rule error fails the run with its message
    requests_mock.post(RUN_RULE_URL, json=[{"progressPercent": 10}, item])
    with pytest.raises(HuntExecutionError, match=message):
        make_client().run_rule("rule x {}", START, END, 10, RunDeadline(30))
