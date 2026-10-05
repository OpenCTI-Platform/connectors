from unittest.mock import MagicMock

import pytest
import requests
from connector import TemplateConnector
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    NativeQuery,
    RunDeadline,
)

SIGMA_RULE = """
title: Encoded PowerShell
status: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
"""

EVENT = {
    "event_type": "INTERNAL_HUNT",
    "mode": "execute",
    "hunt_run": {"id": "run-1", "attempt": 1, "trigger": "manual"},
    "hunt": {
        "id": "hunt-1",
        "standard_id": "hunt--0b7c7d6b-1f47-4c1f-9b37-6b0b6d7a0001",
        "name": "Encoded PowerShell",
        "sigma_rule": SIGMA_RULE,
        "expected_observables": ["IPv4-Addr"],
        "techniques": [
            {"standard_id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"}
        ],
    },
    "time_window": {"start": "2026-10-03T00:00:00Z", "end": "2026-10-04T00:00:00Z"},
    "limits": {"max_results": 10, "timeout_seconds": 30},
    "security_platform": {
        "id": "platform-1",
        "standard_id": "identity--5b1a4c88-5ac7-4c7f-9d8c-9a5f2e8d7c01",
        "name": "Test SIEM",
    },
}


@pytest.fixture
def connector(connector_settings, helper) -> TemplateConnector:
    """A started connector with a mocked pycti helper."""
    instance = TemplateConnector(connector_settings)
    instance._helper = helper
    instance._logger = MagicMock()
    instance.post_init()
    return instance


def test_translate_uses_the_configured_pipeline(connector):
    # Given/When a Sigma rule is translated
    query = connector.translate(SIGMA_RULE, None)

    # Then the pySigma backend produces the platform query
    assert query.language == "opensearch-lucene"
    assert query.translated is True
    assert "CommandLine" in query.query


def test_execute_maps_platform_events(connector, requests_mock):
    # Given a platform returning two events out of three hits
    requests_mock.post(
        "https://siem.example.com/api/search",
        json={
            "total": 3,
            "events": [
                {"@timestamp": "2026-10-03T10:00:00Z", "process": {"pid": 4}},
                {"@timestamp": "", "dest_ip": "8.8.8.8"},
            ],
        },
    )
    window = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")

    # When the query is executed
    result = connector.execute(
        NativeQuery(language="opensearch-lucene", query="q"), window, HuntLimits()
    )

    # Then the events are flattened and the total is kept
    assert result.hits_count == 3
    assert result.truncated is True
    assert result.events[0].fields == {
        "@timestamp": "2026-10-03T10:00:00Z",
        "process.pid": 4,
    }
    assert result.events[1].timestamp is None
    body = requests_mock.last_request.json()
    assert body["query"] == "q"
    assert body["indices"] == ["*"]
    assert requests_mock.last_request.headers["Authorization"] == "Bearer test-api-key"


def test_execute_reports_platform_errors(connector, requests_mock):
    # Given a platform rejecting the search with an explanation
    requests_mock.post(
        "https://siem.example.com/api/search",
        status_code=400,
        json={"error": {"reason": "unknown field"}},
    )
    window = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")

    # When/Then the error is raised as an execution error with the platform message
    with pytest.raises(HuntExecutionError, match="search failed.*unknown field"):
        connector.execute(NativeQuery(language="x", query="q"), window, HuntLimits())


def test_execute_reports_platform_timeouts(connector, requests_mock):
    # Given a platform that does not answer in time
    requests_mock.post(
        "https://siem.example.com/api/search", exc=requests.exceptions.ReadTimeout
    )
    window = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")

    # When/Then the run times out
    with pytest.raises(HuntTimeoutError):
        connector.execute(NativeQuery(language="x", query="q"), window, HuntLimits())


def test_execute_requires_start(connector_settings):
    # Given a connector that is not started
    connector = TemplateConnector(connector_settings)
    window = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")

    # When/Then the client is missing
    with pytest.raises(RuntimeError):
        connector.execute(NativeQuery(language="x", query="q"), window, HuntLimits())


def test_process_message_runs_the_hunt(connector, helper, requests_mock):
    # Given a platform returning one event with a public IP
    requests_mock.post(
        "https://siem.example.com/api/search",
        json={"total": 1, "events": [{"dest_ip": "8.8.8.8"}]},
    )

    # When a hunt run is processed
    message = connector.process_message(EVENT)

    # Then the knowledge is sent and the completed run is reported
    assert "1 hit(s)" in message
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert {obj["type"] for obj in sent} == {"ipv4-addr", "observed-data", "sighting"}
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 1


def test_process_message_preview_never_executes(connector, helper, requests_mock):
    # Given a preview run
    event = {**EVENT, "mode": "preview"}

    # When it is processed
    connector.process_message(event)

    # Then nothing is executed and the translation is reported
    assert requests_mock.call_count == 0
    _, kwargs = helper.report_hunt_run.call_args
    assert "CommandLine" in kwargs["translated_query"]


def test_process_message_reports_failed_runs(connector, helper, requests_mock):
    # Given a platform rejecting the credentials
    requests_mock.post("https://siem.example.com/api/search", status_code=401)

    # When/Then the run fails, is reported as failed and no knowledge is sent
    with pytest.raises(HuntExecutionError):
        connector.process_message(EVENT)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    # The error names what the account lacks, in plain words
    assert "Access denied" in kwargs["error"]
    assert "TEMPLATE_API_KEY" in kwargs["error"]
    helper.send_stix2_bundle.assert_not_called()


def test_connector_declares_its_permissions_and_setup_documentation(connector):
    # Given/When the connector registers its platform
    permissions = dict(connector.required_permissions)

    # Then OpenCTI receives what the account needs and where it is documented
    assert "search:read" in permissions
    assert connector.documentation_url.startswith("https://docs.opencti.io/")


def test_connection_checks_pass_with_a_searchable_account(connector, requests_mock):
    # Given a platform answering the test search
    requests_mock.post(
        "https://siem.example.com/api/search", json={"total": 0, "events": []}
    )

    # When the connection is tested
    checks = connector.connection_checks(RunDeadline(30))

    # Then every check passes
    assert checks
    assert all(check.ok for check in checks)


def test_connection_checks_name_the_missing_permission(connector, requests_mock):
    # Given an API key lacking the search permission
    requests_mock.post("https://siem.example.com/api/search", status_code=403)

    # When the connection is tested
    checks = connector.connection_checks(RunDeadline(30))

    # Then the failed check names the permission to grant
    failed = [check for check in checks if not check.ok]
    assert failed
    assert "search:read" in failed[0].message
