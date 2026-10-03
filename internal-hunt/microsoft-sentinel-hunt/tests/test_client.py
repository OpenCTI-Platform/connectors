from datetime import datetime, timezone

import pytest
import requests
from azure.core.exceptions import ClientAuthenticationError
from conftest import API_URL, QUERY_URL, FakeCredential, table
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
)
from microsoft_sentinel_hunt.client import LogAnalyticsClient, iso_time
from microsoft_sentinel_hunt.connector import RAW_COLUMNS

START = datetime(2026, 10, 3, tzinfo=timezone.utc)
END = datetime(2026, 10, 4, tzinfo=timezone.utc)


def _client(credential=None, workspaces=None, api_url=API_URL) -> LogAnalyticsClient:
    return LogAnalyticsClient(
        api_url=api_url,
        workspace_id="ws-1",
        credential=credential or FakeCredential(),
        additional_workspaces=workspaces or [],
        raw_columns=RAW_COLUMNS,
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

    # When/Then the Log Analytics message is reported
    with pytest.raises(
        HuntExecutionError, match="query failed.*invalid properties"
    ) as err:
        _client().query("T | whre x", START, END, RunDeadline(30))
    assert "HTTP 400" in str(err.value)


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
