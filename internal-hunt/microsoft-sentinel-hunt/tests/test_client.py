from datetime import datetime, timezone
from unittest.mock import patch

import pytest
import requests
from azure.core.exceptions import ClientAuthenticationError
from azure.core.pipeline.transport import RequestsTransport
from conftest import API_URL, QUERY_URL, FakeCredential, table
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from microsoft_sentinel_hunt.client import (
    TOKEN_TIMEOUT_SECONDS,
    LogAnalyticsClient,
    TokenRequestTransport,
    iso_time,
)
from microsoft_sentinel_hunt.connector import RAW_COLUMNS

START = datetime(2026, 10, 3, tzinfo=timezone.utc)
END = datetime(2026, 10, 4, tzinfo=timezone.utc)


def _client(
    credential=None, workspaces=None, api_url=API_URL, token_transport=None
) -> LogAnalyticsClient:
    return LogAnalyticsClient(
        api_url=api_url,
        workspace_id="ws-1",
        credential=credential or FakeCredential(),
        additional_workspaces=workspaces or [],
        raw_columns=RAW_COLUMNS,
        token_transport=token_transport,
    )


def test_iso_time_formats_utc_milliseconds():
    # Given/When/Then times are sent in UTC with milliseconds
    value = datetime(2026, 10, 3, 12, 30, 5, 123456, tzinfo=timezone.utc)
    assert iso_time(value) == "2026-10-03T12:30:05.123Z"


def test_query_sends_the_window_and_decodes_rows(requests_mock):
    # Given a workspace answering with typed columns
    requests_mock.post(
        QUERY_URL,
        json=table(
            [
                ("TimeGenerated", "datetime"),
                ("Computer", "string"),
                ("Details", "dynamic"),
                ("EventData", "dynamic"),
                ("Tags", "dynamic"),
            ],
            [
                [
                    "2026-10-03T10:00:00Z",
                    "ws1",
                    '{"ip": "8.8.8.8"}',
                    '{"raw": true}',
                    "not json",
                ],
                ["2026-10-03T11:00:00Z", "ws2", None, "", ""],
            ],
        ),
    )
    credential = FakeCredential()

    # When a query runs
    result = _client(credential, workspaces=["ws-2"]).query(
        "SecurityEvent", START, END, RunDeadline(30)
    )

    # Then the window, the token and the server wait are sent
    request = requests_mock.last_request
    assert request.json() == {
        "query": "SecurityEvent",
        "timespan": "2026-10-03T00:00:00.000Z/2026-10-04T00:00:00.000Z",
        "workspaces": ["ws-2"],
    }
    assert request.headers["Authorization"] == "Bearer entra-token"
    assert request.headers["Prefer"].startswith("wait=")
    assert credential.scopes == ["https://api.loganalytics.io/.default"]
    # And dynamic columns are decoded, raw payloads kept as text
    assert result.rows[0]["Details"] == {"ip": "8.8.8.8"}
    assert result.rows[0]["EventData"] == '{"raw": true}'
    assert result.rows[0]["Tags"] == "not json"
    assert result.rows[1]["Details"] is None
    assert result.partial_error is None


def test_query_uses_the_cloud_of_the_api_url(requests_mock):
    # Given an Azure Government workspace
    requests_mock.post(
        "https://api.loganalytics.us/v1/workspaces/ws-1/query", json={"tables": []}
    )
    credential = FakeCredential()

    # When/Then the token is requested for the Government query API
    result = _client(credential, api_url="https://api.loganalytics.us/").query(
        "T", START, END, RunDeadline(30)
    )
    assert result.rows == []
    assert credential.scopes == ["https://api.loganalytics.us/.default"]
    assert "workspaces" not in requests_mock.last_request.json()


def test_query_reports_partial_errors(requests_mock):
    # Given a workspace returning incomplete results
    answer = table([("Computer", "string")], [["ws1"]])
    answer["error"] = {
        "code": "PartialError",
        "message": "There were some errors when processing your query.",
    }
    requests_mock.post(QUERY_URL, json=answer)

    # When/Then the rows and the partial error are returned
    result = _client().query("T", START, END, RunDeadline(30))
    assert result.rows == [{"Computer": "ws1"}]
    assert result.partial_error.startswith("There were some errors")


def test_query_rejects_unexpected_answers(requests_mock):
    # Given a workspace answering with a list
    requests_mock.post(QUERY_URL, json=["unexpected"])

    # When/Then the query fails
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        _client().query("T", START, END, RunDeadline(30))


def test_query_reports_the_log_analytics_error(requests_mock):
    # Given a syntax error
    requests_mock.post(
        QUERY_URL,
        status_code=400,
        json={
            "error": {
                "code": "BadArgumentError",
                "message": "The request had some invalid properties",
                "innererror": {"message": "Query could not be parsed at 'whre'"},
            }
        },
    )

    # When/Then the Log Analytics messages, inner errors included, are reported
    with pytest.raises(HuntExecutionError) as err:
        _client().query("T | whre x", START, END, RunDeadline(30))
    assert str(err.value) == (
        "The Log Analytics query failed (HTTP 400 on POST /v1/workspaces/ws-1/query): "
        "The request had some invalid properties - Query could not be parsed at 'whre'"
    )


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({"exc": requests.exceptions.ConnectionError}, id="network"),
        pytest.param({"status_code": 401}, id="no_body"),
        pytest.param(
            {"status_code": 500, "json": {"error": {"code": "x"}}}, id="no_message"
        ),
    ],
)
def test_query_keeps_generic_errors(requests_mock, response):
    # Given a failure without Log Analytics error messages
    requests_mock.post(QUERY_URL, **response)

    # When/Then the generic hunt error is raised
    with pytest.raises(HuntExecutionError, match="The Log Analytics query failed"):
        _client().query("T", START, END, RunDeadline(30))


def test_query_maps_authentication_failures():
    # Given a credential refused by Microsoft Entra
    credential = FakeCredential()
    credential.get_token = lambda *_, **__: (_ for _ in ()).throw(
        ClientAuthenticationError("AADSTS7000215: Invalid client secret provided.")
    )

    # When/Then the run fails with the Entra message
    with pytest.raises(HuntExecutionError, match="Entra authentication failed.*AADSTS"):
        _client(credential).query("T", START, END, RunDeadline(30))


def test_query_maps_timeouts(requests_mock):
    # Given a workspace that does not answer in time
    requests_mock.post(QUERY_URL, exc=requests.exceptions.ReadTimeout)

    # When/Then the run times out
    with pytest.raises(HuntTimeoutError):
        _client().query("T", START, END, RunDeadline(30))


def test_token_acquisition_is_bounded_by_the_run_deadline(requests_mock):
    # Given a credential sending its token requests through the client transport
    requests_mock.post(QUERY_URL, json=table([], []))
    transport = TokenRequestTransport()
    bounds = []

    class BoundCredential(FakeCredential):
        def get_token(self, *scopes, **kwargs):
            bounds.append(transport.deadline)
            return super().get_token(*scopes, **kwargs)

    deadline = RunDeadline(30)

    # When a query runs
    _client(BoundCredential(), token_transport=transport).query(
        "T", START, END, deadline
    )

    # Then the token was requested under the run deadline, released afterwards
    assert bounds == [deadline]
    assert transport.deadline is None


def test_token_transport_bounds_every_request_by_the_deadline():
    # Given a token transport and a run deadline of 12 seconds
    now = [0.0]
    deadline = RunDeadline(12, clock=lambda: now[0])
    transport = TokenRequestTransport()

    with patch.object(RequestsTransport, "send", return_value="answer") as send:
        # When/Then outside a run, a token request waits at most the token timeout
        assert transport.send("token-request") == "answer"
        assert send.call_args.kwargs == {
            "connection_timeout": TOKEN_TIMEOUT_SECONDS,
            "read_timeout": TOKEN_TIMEOUT_SECONDS,
        }
        with transport.bounded_by(deadline):
            # During the run, at most the time left before its deadline
            transport.send("token-request")
            assert send.call_args.kwargs == {
                "connection_timeout": 12.0,
                "read_timeout": 12.0,
            }
            # Once the deadline is reached, no request is sent (retries included)
            now[0] = 13.0
            with pytest.raises(HuntTimeoutError, match="Microsoft Entra"):
                transport.send("token-request")
        assert send.call_count == 2
    assert transport.deadline is None


def test_stalled_authentication_is_reported_as_a_timeout():
    # Given a credential chain stalling until the deadline, then reporting an authentication error
    now = [0.0]
    deadline = RunDeadline(30, clock=lambda: now[0])

    def _stall(*_, **__):
        now[0] = 31.0
        raise ClientAuthenticationError(
            "DefaultAzureCredential failed to retrieve a token"
        )

    credential = FakeCredential()
    credential.get_token = _stall

    # When/Then the run times out instead of failing on authentication
    with pytest.raises(HuntTimeoutError, match="Microsoft Entra authentication"):
        _client(credential, token_transport=TokenRequestTransport()).query(
            "T", START, END, deadline
        )
