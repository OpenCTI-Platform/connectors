import hashlib
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from conftest import NAMESPACE, make_settings
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    HuntUnsupportedPyctiError,
    NativeQuery,
)
from splunk_hunt import SplunkHuntConnector
from splunk_hunt.connector import build_search, split_first_pipe

JOB = f"{NAMESPACE}/search/jobs/sid-1"
WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")


def _mock_job(requests_mock, rows, total=None):
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(
        JOB,
        json={
            "entry": [
                {
                    "content": {
                        "isDone": True,
                        "resultCount": len(rows) if total is None else total,
                    }
                }
            ]
        },
    )
    requests_mock.get(
        f"{NAMESPACE}/search/v2/jobs/sid-1/results", json={"results": rows}
    )
    requests_mock.delete(JOB, json={})


@pytest.mark.parametrize(
    "query, expected",
    [
        ('a="x|y" b=1 | stats count', ('a="x|y" b=1', "| stats count")),
        ("a='q\\'|' | head 1", ("a='q\\'|'", "| head 1")),
        ("a=1", ("a=1", "")),
    ],
)
def test_split_first_pipe_ignores_quoted_pipes(query, expected):
    # Given/When/Then the search part ends at the first unquoted pipe
    assert split_first_pipe(query) == expected


@pytest.mark.parametrize(
    "query, prefix, expected",
    [
        ("a=1 OR b=2", "", "search (a=1 OR b=2)"),
        ("a=1", "index=x OR index=y", "search (index=x OR index=y) (a=1)"),
        ("search a=1 | stats count", "index=x", "search (index=x) (a=1) | stats count"),
        (
            "| tstats count from datamodel=Endpoint",
            "index=x",
            "| tstats count from datamodel=Endpoint",
        ),
        ("| inputlookup x", "", "| inputlookup x"),
        ("search | head 1", "index=x", "search (index=x) | head 1"),
    ],
)
def test_build_search(query, prefix, expected):
    # Given/When/Then searches get the search command and the parenthesized prefix
    assert build_search(query, prefix) == expected


def test_translate_with_the_configured_pipeline(connector_factory):
    # Given/When a Sigma rule is translated with the default Splunk Windows pipeline
    connector = connector_factory()
    query = connector.translate(connector.parse_request(_event()).hunt.sigma_rule, None)

    # Then the SPL query is produced
    assert query.language == "spl"
    assert query.query == 'Image="*\\\\powershell.exe" CommandLine="* -enc *"'
    assert query.fields == ("Image", "CommandLine")


def test_translate_with_the_cim_data_model(connector_factory):
    # Given the CIM data model output format
    connector = connector_factory(
        {"splunk_hunt": {"sigma_pipeline": "splunk_cim", "output_format": "data_model"}}
    )

    # When/Then a tstats search is produced
    query = connector.translate(connector.parse_request(_event()).hunt.sigma_rule, None)
    assert query.query.startswith("| tstats")
    assert "datamodel=Endpoint.Processes" in query.query


def test_translate_rejects_unknown_pipelines(connector_factory):
    # Given/When/Then an unknown pipeline is rejected
    connector = connector_factory()
    with pytest.raises(HuntTranslationError, match="splunk_cim"):
        connector.translate(_event()["hunt"]["sigma_rule"], "unknown")


def test_combine_queries(connector_factory):
    # Given a connector
    connector = connector_factory()

    # When/Then plain searches are joined, pipelines are rejected
    assert connector.combine_queries(["a=1"]) == "a=1"
    assert connector.combine_queries(["a=1", "b=2"]) == "(a=1) OR (b=2)"
    with pytest.raises(HuntTranslationError, match="2 Splunk pipelines"):
        connector.combine_queries(["a=1 | stats count", "b=2"])


def test_execute_maps_results(connector_factory, requests_mock):
    # Given a search returning one event out of 7 matches
    _mock_job(
        requests_mock,
        [{"_time": "2026-10-03T10:00:00.000+00:00", "host": "ws1", "_raw": "raw"}],
        total=7,
    )
    connector = connector_factory({"splunk_hunt": {"search_prefix": "index=main"}})

    # When the query is executed
    result = connector.execute(
        NativeQuery(language="spl", query="a=1 OR b=2"), WINDOW, HuntLimits()
    )

    # Then the search is scoped and the event mapped
    assert "search=search+%28index%3Dmain%29+%28a%3D1+OR+b%3D2%29" in (
        requests_mock.request_history[0].text
    )
    assert result.hits_count == 7
    assert result.truncated is True
    assert result.events[0].timestamp == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)
    assert result.events[0].fields["host"] == "ws1"


def test_execute_requires_start():
    # Given/When/Then a connector that is not started has no client
    connector = SplunkHuntConnector(make_settings())
    with pytest.raises(RuntimeError):
        connector.execute(NativeQuery(language="spl", query="x"), WINDOW, HuntLimits())


def test_on_timeout_cancels_the_active_job(connector_factory):
    # Given a connector with a running job
    connector = connector_factory()
    connector.client = MagicMock()

    query = NativeQuery(language="spl", query="x")

    # When/Then the job of that query is cancelled, and nothing happens without client
    connector.on_timeout(query)
    connector.client.cancel.assert_called_once_with(id(query))
    connector.client = None
    connector.on_timeout(NativeQuery(language="spl", query="x"))


def test_process_message_reports_hits_and_sends_knowledge(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given Splunk events with a public destination IP and a benign one
    _mock_job(
        requests_mock,
        [
            {"_time": "2026-10-03T10:00:00Z", "dest_ip": "8.8.8.8", "host": "ws1"},
            {"_time": "2026-10-03T11:00:00Z", "dest_ip": "1.1.1.1", "host": "sccm01"},
        ],
    )
    hunt_event["hunt"]["benign_patterns"] = ["sccm"]

    # When the hunt run is processed
    message = connector_factory().process_message(hunt_event)

    # Then the sighting and the observed IP are sent, and the run reported
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert {obj["type"] for obj in sent} == {"ipv4-addr", "observed-data", "sighting"}
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 1
    assert kwargs["query_language"] == "spl"
    assert kwargs["translated_query"].startswith("Image=")
    assert all(item["field"] != "_raw" for item in kwargs["evidence_sample"])
    assert "1 hit(s)" in message


def test_process_message_preview(connector_factory, helper, requests_mock, hunt_event):
    # Given a preview run
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then Splunk is never called
    assert requests_mock.call_count == 0
    assert helper.report_hunt_run.call_args.args == ("run-1", "completed")


def test_process_message_reports_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given Splunk rejects the credentials
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", status_code=401, json={})

    # When/Then the run fails, is reported as failed and sends no knowledge
    with pytest.raises(HuntExecutionError, match="search job creation failed"):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "Unauthorized" in kwargs["error"]
    assert kwargs["translated_query"].startswith("Image=")
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_executes_native_queries_verbatim(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a hunt with a native SPL query for Splunk
    _mock_job(requests_mock, [])
    hunt_event["hunt"]["native_query"] = {
        "platform": "splunk",
        "language": "spl",
        "query": "| tstats count from datamodel=Endpoint.Processes",
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the generating command is sent as is and no knowledge is produced
    assert "search=%7C+tstats" in requests_mock.request_history[0].text
    _, kwargs = helper.report_hunt_run.call_args
    assert kwargs["hits_count"] == 0
    assert kwargs["translated_query"].startswith("| tstats")
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_times_out_and_cancels_the_job(
    connector_factory, helper, hunt_event
):
    # Given a Splunk search that never completes within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.search.side_effect = lambda *args: release.wait(5)
    hunt_event["limits"]["timeout_seconds"] = 1

    # When/Then the run times out, the job is cancelled and the run reported as a timeout
    try:
        with pytest.raises(HuntTimeoutError):
            connector.process_message(hunt_event)
    finally:
        release.set()
    connector.client.cancel.assert_called_once()
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "timeout")
    assert "1 seconds" in kwargs["error"]


def test_process_message_redacts_evidence_and_maps_stix(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given results with a long command line, a private and a public IP
    command_line = "powershell.exe -enc " + "A" * 400
    _mock_job(
        requests_mock,
        [
            {
                "_time": "2026-10-03T10:00:00.000+00:00",
                "CommandLine": command_line,
                "dest_ip": "8.8.8.8",
                "src_ip": "10.0.0.5",
                "_raw": "secret raw event",
            },
            {
                "_time": "2026-10-03T12:00:00.000+00:00",
                "CommandLine": command_line,
                "dest_ip": "8.8.8.8",
                "src_ip": "10.0.0.6",
            },
        ],
    )
    hunt_event["limits"]["evidence_max_value_length"] = 32

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then evidence values are hashed and truncated, raw events never reported
    _, kwargs = helper.report_hunt_run.call_args
    evidence = {item["field"]: item for item in kwargs["evidence_sample"]}
    assert (
        evidence["CommandLine"]["value_hash"]
        == hashlib.sha256(command_line.encode()).hexdigest()
    )
    assert evidence["CommandLine"]["value_preview"] == command_line[:32]
    assert evidence["CommandLine"]["count"] == 2
    assert "_raw" not in evidence
    assert kwargs["distinct_entities"] == 3
    # And the bundle holds the sighting on the platform and the public IP only
    sent = {obj["type"]: obj for obj in helper.stix2_create_bundle.call_args.args[0]}
    sighting = sent["sighting"]
    assert sighting["sighting_of_ref"] == (
        "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"
    )
    assert sighting["where_sighted_refs"] == [
        "identity--5b1a4c88-5ac7-4c7f-9d8c-9a5f2e8d7c01"
    ]
    assert sighting["count"] == 2
    assert sighting["object_marking_refs"] == [
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    ]
    assert sent["ipv4-addr"]["value"] == "8.8.8.8"
    assert sent["observed-data"]["number_observed"] == 2
    assert sorted(kwargs["result_ids"]) == sorted(
        obj["id"] for obj in helper.stix2_create_bundle.call_args.args[0]
    )
    assert helper.send_stix2_bundle.call_args.kwargs["work_id"] == "work-1"


SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"


def test_start_registers_the_splunk_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = SplunkHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the Splunk platform is registered and the hunt queue consumed
    helper = helper_cls.return_value
    helper.register_hunt_platform.assert_called_once_with(
        platform="splunk",
        languages=["spl"],
        security_platform_name="Splunk",
        security_platform_type="SIEM",
        supports_preview=True,
        max_concurrent_runs=None,
    )
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )
    assert connector.client is not None


def test_start_fails_fast_without_pycti_hunt_support():
    # Given a pycti without the hunt API
    connector = SplunkHuntConnector(make_settings())
    with (
        patch(
            f"{SDK_CONNECTOR}.ensure_pycti_hunt_support",
            side_effect=HuntUnsupportedPyctiError("pycti 7.0 does not support hunts"),
        ),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When/Then the connector stops before connecting to OpenCTI
        with pytest.raises(HuntUnsupportedPyctiError, match="does not support"):
            connector.start()
    helper_cls.assert_not_called()


def _event():
    from conftest import HUNT_EVENT

    return HUNT_EVENT
