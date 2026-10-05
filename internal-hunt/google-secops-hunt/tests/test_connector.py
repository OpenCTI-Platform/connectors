import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from conftest import (
    RUN_RULE_URL,
    UDM_SEARCH_URL,
    FakeCredentials,
    make_settings,
    udm_event,
)
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntQueryRejectedError,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from google_secops_hunt import GoogleSecopsHuntConnector
from google_secops_hunt.client import SearchResult
from google_secops_hunt.connector import SCOPES, udm_names, udm_query_fields

FIXTURES = Path(__file__).parent / "fixtures"
WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
TWO_RULES = """
title: First
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\a.exe'
  condition: selection
---
title: Second
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\b.exe'
  condition: selection
"""


def test_build_credentials_from_the_service_account():
    # Given the configured service account
    connector = GoogleSecopsHuntConnector(make_settings())
    with patch(
        "google_secops_hunt.connector.service_account.Credentials"
        ".from_service_account_info"
    ) as from_info:
        # When the credentials are built
        credentials = connector.build_credentials()

    # Then the service account information is complete, with the cloud scope
    assert credentials is from_info.return_value
    info = from_info.call_args.args[0]
    assert from_info.call_args.kwargs == {"scopes": SCOPES}
    assert info["type"] == "service_account"
    assert info["project_id"] == "hunt-project"
    assert info["private_key"].startswith("-----BEGIN PRIVATE KEY-----\n")
    assert info["client_email"] == "hunter@hunt-project.iam.gserviceaccount.com"
    assert info["token_uri"] == "https://oauth2.googleapis.com/token"


def test_translate_into_a_udm_search(connector_factory, hunt_event):
    # Given/When a Sigma rule is translated with the defaults
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], None)

    # Then it is a UDM search with UDM fields
    assert query.language == "udm"
    assert "target.process" in query.query
    assert query.translated is True


def test_translate_into_a_yara_l_rule(connector_factory, hunt_event):
    # Given a connector translating into YARA-L
    connector = connector_factory({"google_secops_hunt": {"query_language": "yara-l"}})

    # When/Then the query is a full YARA-L rule
    query = connector.translate(hunt_event["hunt"]["sigma_rule"], None)
    assert query.language == "yara-l"
    assert query.query.lstrip().startswith("rule ")
    assert "events:" in query.query


def test_translate_rejects_unknown_pipelines(connector_factory, hunt_event):
    # Given/When/Then an unknown pipeline is rejected with the supported ones
    with pytest.raises(HuntTranslationError, match="secops_udm"):
        connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "splunk_cim")


def test_udm_searches_are_joined_with_or(connector_factory):
    # Given/When a Sigma document with two rules is translated into UDM
    query = connector_factory().translate(TWO_RULES, None).query

    # Then both searches are joined with OR
    assert query.startswith("(")
    assert ") OR (" in query


def test_yara_l_rules_cannot_be_joined(connector_factory):
    # Given a YARA-L connector
    connector = connector_factory({"google_secops_hunt": {"query_language": "yara-l"}})

    # When/Then two rules cannot be combined
    with pytest.raises(HuntTranslationError, match="2 queries"):
        connector.translate(TWO_RULES, None)


def test_execute_udm_search_maps_events(connector_factory, requests_mock):
    # Given a UDM search answer
    requests_mock.get(
        UDM_SEARCH_URL,
        json={
            "events": [udm_event("2026-10-03T10:00:00Z", principal={"hostname": "ws1"})]
        },
    )

    # When the native query runs
    result = connector_factory().execute(
        NativeQuery(language="udm", query='  principal.hostname = "ws1"  '),
        WINDOW,
        HuntLimits(),
    )

    # Then the query is stripped and the events flattened with their timestamp
    assert "principal.hostname" in requests_mock.last_request.url
    assert result.hits_count == 1
    assert result.events[0].timestamp == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)
    assert result.events[0].fields["principal.hostname"] == "ws1"
    assert result.truncated is False


def test_execute_yara_l_counts_detections(connector_factory):
    # Given a client returning three detections but one dated event
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.run_rule.return_value = SearchResult(
        [{"detectionTime": "2026-10-03T11:00:00Z"}], 3, True
    )

    # When the YARA-L rule runs
    result = connector.execute(
        NativeQuery(language="yara-l", query="rule x {}"), WINDOW, HuntLimits()
    )

    # Then the detections are counted and dated by their detection time
    assert (result.hits_count, result.truncated) == (3, True)
    assert result.events[0].timestamp == datetime(2026, 10, 3, 11, tzinfo=timezone.utc)
    connector.client.udm_search.assert_not_called()


def test_execute_yara_l_counts_a_detection_once_whatever_its_events(
    connector_factory,
):
    # Given one detection referencing three events and another referencing one
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.run_rule.return_value = SearchResult(
        [
            udm_event("2026-10-03T10:00:00Z", principal={"hostname": "ws1"}),
            udm_event("2026-10-03T10:00:01Z", principal={"hostname": "ws2"}),
            udm_event("2026-10-03T10:00:02Z", principal={"hostname": "ws3"}),
            udm_event("2026-10-03T11:00:00Z", principal={"hostname": "ws4"}),
        ],
        2,
        False,
        ["detection-1", "detection-1", "detection-1", "detection-2"],
    )

    # When the YARA-L rule runs
    result = connector.execute(
        NativeQuery(language="yara-l", query="rule x {}"), WINDOW, HuntLimits()
    )

    # Then the hits are the two detections, every referenced event kept as evidence
    assert result.hits_count == 2
    assert len(result.events) == 4
    assert [event.detection for event in result.events] == [
        "detection-1",
        "detection-1",
        "detection-1",
        "detection-2",
    ]


def test_execute_events_without_time(connector_factory):
    # Given a client returning an event without time
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.udm_search.return_value = SearchResult([{"a": 1}], None, False)

    # When/Then the event has no timestamp
    result = connector.execute(
        NativeQuery(language="udm", query="x"), WINDOW, HuntLimits()
    )
    assert result.events[0].timestamp is None


def test_execute_requires_start():
    # Given/When/Then a connector that is not started has no client
    connector = GoogleSecopsHuntConnector(make_settings())
    with pytest.raises(RuntimeError):
        connector.execute(NativeQuery(language="udm", query="x"), WINDOW, HuntLimits())


def test_process_message_reports_hits_and_sends_knowledge(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given events with a public IP, a private IP and a benign host
    requests_mock.get(
        UDM_SEARCH_URL,
        json={
            "events": [
                udm_event(
                    "2026-10-03T10:00:00Z",
                    principal={"hostname": "ws1"},
                    target={"ip": "8.8.8.8"},
                ),
                udm_event(
                    "2026-10-03T11:00:00Z",
                    principal={"hostname": "ws2"},
                    target={"ip": "10.0.0.1"},
                ),
                udm_event(
                    "2026-10-03T12:00:00Z",
                    principal={"hostname": "sccm01"},
                    target={"ip": "1.1.1.1"},
                ),
            ]
        },
    )
    hunt_event["hunt"]["benign_patterns"] = ["/^sccm\\d+$/"]

    # When the hunt run is processed
    message = connector_factory().process_message(hunt_event)

    # Then the run is reported with the translated query and hashed evidence
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["query_language"] == "udm"
    fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert "metadata.id" not in fields
    for item in kwargs["evidence_sample"]:
        assert len(item["value_hash"]) == 64
    assert "2 hit(s)" in message
    # And the sightings of the technique and the indicator, with the public IP only
    sent = helper.stix2_create_bundle.call_args.args[0]
    sightings = [obj for obj in sent if obj["type"] == "sighting"]
    assert sorted(obj["sighting_of_ref"] for obj in sightings) == [
        "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
        "indicator--a1b2c3d4-0000-4000-8000-000000000001",
    ]
    assert all(
        obj["created_by_ref"] == "identity--7b82b010-b1c0-4dae-981f-7756374a17df"
        for obj in sent
        if obj["type"] in ("sighting", "observed-data")
    )
    assert [obj["value"] for obj in sent if obj["type"] == "ipv4-addr"] == ["8.8.8.8"]


def test_process_message_evidence_is_hashed_and_truncated(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a long command line
    command_line = "powershell -enc " + "B" * 300
    event = {"udm": {"target": {"process": {"command_line": command_line}}}}
    requests_mock.get(UDM_SEARCH_URL, json={"events": [event, event]})
    hunt_event["limits"]["evidence_max_value_length"] = 20

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the evidence holds the hash of the full value and a truncated preview
    evidence = helper.report_hunt_run.call_args.kwargs["evidence_sample"]
    assert evidence == [
        {
            "field": "target.process.command_line",
            "value_hash": hashlib.sha256(command_line.encode()).hexdigest(),
            "value_preview": command_line[:20],
            "count": 2,
        }
    ]


def _recorded(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_udm_names_follow_udm_search_and_keep_parser_keys():
    # Given a UDM event as the Chronicle API answers it, in camelCase
    event = {
        "metadata": {"eventTimestamp": "t", "baseLabels": {"logTypes": ["X"]}},
        "target": {"process": {"commandLine": "c", "file": {"fullPath": "p"}}},
        "about": [{"ipAddress": "1"}],
        "additional": {"CategoryName": "v"},
    }

    # When/Then the fields are named as in UDM search, the parser keys kept
    assert udm_names(event) == {
        "metadata": {"event_timestamp": "t", "base_labels": {"log_types": ["X"]}},
        "target": {"process": {"command_line": "c", "file": {"full_path": "p"}}},
        "about": [{"ip_address": "1"}],
        "additional": {"CategoryName": "v"},
    }


@pytest.mark.parametrize(
    "query, fields",
    [
        pytest.param(
            'target.process.command_line = /-enc/ nocase AND principal.hostname = "ws1"'
            ' AND target.process.command_line != ""',
            ("target.process.command_line", "principal.hostname"),
            id="udm",
        ),
        pytest.param(
            'rule r { events: $e.metadata.event_type = "PROCESS_LAUNCH" and '
            "re.regex($e.target.process.file.full_path, `powershell`) condition: $e }",
            ("metadata.event_type", "target.process.file.full_path"),
            id="yara_l",
        ),
    ],
)
def test_udm_query_fields(query, fields):
    # Given/When/Then the UDM fields a native query references are found, in order
    assert udm_query_fields(query) == fields


def test_process_message_reports_each_hit_and_dates_the_sightings(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a recorded UDM search answer, in the camelCase of the Chronicle API
    requests_mock.get(UDM_SEARCH_URL, json=_recorded("udm_search_process_launch.json"))

    # When the Sigma hunt runs
    connector_factory().process_message(hunt_event)

    # Then the per-field evidence starts with the matched fields, without bookkeeping
    kwargs = helper.report_hunt_run.call_args.kwargs
    fields = [item["field"] for item in kwargs["evidence_sample"]]
    assert fields[:3] == [
        "target.process.file.full_path",
        "target.process.command_line",
        "principal.hostname",
    ]
    assert not [
        field
        for field in fields
        if field.startswith(("metadata.base_labels", "metadata.enrichment"))
        or field in ("metadata.id", "metadata.event_timestamp")
    ]
    # And each hit tells what matched, on which host, by whom, which process, when
    first, second = kwargs["hits_sample"]
    command_line = "powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    assert first["event_id"] == "AAAAAJ8xY2QxAAAAAAAAAA=="
    assert first["timestamp"] == "2026-10-03T10:00:00Z"
    assert (first["host"], first["user"]) == ("ws1.corp.example", "alice")
    assert first["process"].endswith("\\powershell.exe")
    matched = {item["field"]: item for item in first["matched"]}
    assert matched["target.process.command_line"] == {
        "field": "target.process.command_line",
        "value_hash": hashlib.sha256(command_line.encode()).hexdigest(),
        "value_preview": command_line,
    }
    assert (second["host"], second["user"]) == ("ws2.corp.example", "bob")
    # And the sightings are dated by the first and last hits, not the run window
    sightings = [
        obj
        for obj in helper.stix2_create_bundle.call_args.args[0]
        if obj["type"] == "sighting"
    ]
    assert {(obj["first_seen"], obj["last_seen"]) for obj in sightings} == {
        ("2026-10-03T10:00:00Z", "2026-10-03T11:30:00Z")
    }


def test_process_message_native_udm_search_reports_the_matched_field(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native UDM search on the host name, and the recorded answer
    requests_mock.get(UDM_SEARCH_URL, json=_recorded("udm_search_process_launch.json"))
    hunt_event["hunt"]["native_query"] = {
        "platform": "google-secops",
        "language": "udm",
        "query": "principal.hostname = /corp\\.example$/",
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then each hit names the field of the search
    hits = helper.report_hunt_run.call_args.kwargs["hits_sample"]
    assert [[item["field"] for item in hit["matched"]] for hit in hits] == [
        ["principal.hostname"],
        ["principal.hostname"],
    ]


def test_process_message_preview(connector_factory, helper, requests_mock, hunt_event):
    # Given a preview run
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then SecOps is never queried
    assert requests_mock.call_count == 0
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["query_language"] == "udm"


def test_process_message_executes_native_yara_l_rules(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native YARA-L rule for Google SecOps
    requests_mock.post(RUN_RULE_URL, json=[{"progressPercent": 100}])
    rule = 'rule hunt { events: $e.metadata.event_type = "PROCESS_LAUNCH" }'
    hunt_event["hunt"]["native_query"] = {
        "platform": "google-secops",
        "language": "yara-l",
        "query": rule,
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the rule runs verbatim and reports no hit
    assert requests_mock.last_request.json()["ruleText"] == rule
    assert helper.report_hunt_run.call_args.kwargs["hits_count"] == 0
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_rejects_unsupported_native_languages(
    connector_factory, helper, hunt_event
):
    # Given a native query in a language the connector does not run
    hunt_event["hunt"]["native_query"] = {
        "platform": "google-secops",
        "language": "kql",
        "query": "DeviceEvents",
    }

    # When/Then the run fails with the supported languages
    with pytest.raises(HuntTranslationError, match="udm, yara-l"):
        connector_factory().process_message(hunt_event)
    assert helper.report_hunt_run.call_args.args == ("run-1", "failed")


def test_process_message_reports_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a service account without the Chronicle permission
    requests_mock.get(
        UDM_SEARCH_URL,
        status_code=403,
        json={"error": {"code": 403, "message": "Permission denied"}},
    )

    # When/Then the run fails and is reported failed with the reason
    with pytest.raises(HuntExecutionError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "Permission denied" in kwargs["error"]
    # A role granted just before the run can take minutes to apply
    assert kwargs["retryable"] is True
    helper.send_stix2_bundle.assert_not_called()


DNS_RULE = """
title: DNS query to a suspicious domain
logsource:
  category: dns
detection:
  selection:
    query|endswith: '.evil.example'
  condition: selection
"""


@pytest.mark.parametrize(
    "mode", [pytest.param("execute", id="run"), pytest.param("preview", id="preview")]
)
def test_untranslatable_sigma_rule_fails_without_retry(
    connector_factory, helper, requests_mock, hunt_event, mode
):
    # Given a Sigma rule using a field the UDM pipeline cannot map
    hunt_event["mode"] = mode
    hunt_event["hunt"]["sigma_rule"] = DNS_RULE

    # When/Then the run fails before any search, as a failure running it again cannot fix
    with pytest.raises(HuntTranslationError, match="Invalid UDM field"):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert kwargs["error"].startswith("HuntTranslationError: Sigma conversion failed")
    assert kwargs["retryable"] is False
    assert requests_mock.call_count == 0


def test_udm_search_rejected_by_secops_fails_without_retry(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native UDM search SecOps refuses to parse
    requests_mock.get(
        UDM_SEARCH_URL,
        status_code=400,
        json={
            "error": {
                "code": 400,
                "message": "parsing: invalid field 'principal.hostnme'",
                "status": "INVALID_ARGUMENT",
            }
        },
    )
    hunt_event["hunt"]["native_query"] = {
        "platform": "google-secops",
        "language": "udm",
        "query": 'principal.hostnme = "ws1"',
    }

    # When/Then the run fails with the SecOps reason, and is not retried
    with pytest.raises(HuntQueryRejectedError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "invalid field 'principal.hostnme'" in kwargs["error"]
    assert kwargs["retryable"] is False


def test_yara_l_rule_that_does_not_compile_fails_without_retry(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a YARA-L rule SecOps cannot compile
    requests_mock.post(
        RUN_RULE_URL,
        json=[{"ruleCompilationError": {"message": "undefined variable $x"}}],
    )
    hunt_event["hunt"]["native_query"] = {
        "platform": "google-secops",
        "language": "yara-l",
        "query": "rule broken { condition: $x }",
    }

    # When/Then the run fails with the compilation error, and is not retried
    with pytest.raises(HuntQueryRejectedError, match="does not compile"):
        connector_factory().process_message(hunt_event)
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert "undefined variable $x" in kwargs["error"]
    assert kwargs["retryable"] is False


def test_process_message_times_out(connector_factory, helper, hunt_event):
    # Given a search that never completes within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.udm_search.side_effect = lambda *args: release.wait(5)
    hunt_event["limits"]["timeout_seconds"] = 1

    # When/Then the run times out and is reported as a timeout
    try:
        with pytest.raises(HuntTimeoutError):
            connector.process_message(hunt_event)
    finally:
        release.set()
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "timeout")
    assert "1 seconds" in kwargs["error"]


def test_start_registers_the_secops_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = GoogleSecopsHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
        patch.object(
            GoogleSecopsHuntConnector,
            "build_credentials",
            return_value=FakeCredentials(),
        ),
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered with both languages and the indicator lookups
    helper = helper_cls.return_value
    helper.register_hunt_platform.assert_called_once_with(
        platform="google-secops",
        languages=["udm", "yara-l"],
        security_platform_name="Google SecOps",
        security_platform_type="SIEM",
        supports_preview=True,
        max_concurrent_runs=None,
        supports_indicators=True,
        required_permissions=[
            {"name": name, "purpose": purpose}
            for name, purpose in GoogleSecopsHuntConnector.required_permissions
        ],
        documentation_url=GoogleSecopsHuntConnector.documentation_url,
    )
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )
    assert connector.client is not None


def test_start_fails_fast_without_the_pycti_hunt_api():
    # Given a pycti without the hunt connector API
    connector = GoogleSecopsHuntConnector(make_settings())
    with (
        patch(
            f"{SDK_CONNECTOR}.ensure_pycti_hunt_support",
            side_effect=RuntimeError("pycti lacks the hunt API"),
        ),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When/Then the connector stops before creating the helper
        with pytest.raises(RuntimeError, match="hunt API"):
            connector.start()
    helper_cls.assert_not_called()
