import hashlib
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from conftest import (
    PPL_URL,
    SEARCH_URL,
    count_answer,
    hits_answer,
    make_settings,
    ppl_answer,
)
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from opensearch_ocsf_hunt import OpenSearchOcsfHuntConnector
from opensearch_ocsf_hunt.client import SearchResult
from opensearch_ocsf_hunt.connector import strip_statement_end

WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
EVENT_MS = 1791021600000
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


def test_translate_into_ppl_over_the_configured_indices(connector_factory, hunt_event):
    # Given/When a Sigma rule is translated with the defaults
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], None)

    # Then it is a PPL query over the configured indices with OCSF fields
    assert query.language == "ppl"
    assert query.query.startswith("source=ocsf-* | where type_uid=100701")
    assert "`process.cmd_line`" in query.query
    assert query.translated is True


def test_translate_without_pipeline(connector_factory, hunt_event):
    # Given/When the hunt disables the pipeline
    query = connector_factory(
        {"opensearch_ocsf_hunt": {"indices": "a-*,b-*"}}
    ).translate(hunt_event["hunt"]["sigma_rule"], "none")

    # Then the Sigma field names are kept, over the configured indices
    assert query.query.startswith("source=a-*,b-* | where ")
    assert "CommandLine" in query.query
    assert "type_uid" not in query.query


def test_translate_into_lucene(connector_factory, hunt_event):
    # Given a connector translating into Lucene
    connector = connector_factory(
        {"opensearch_ocsf_hunt": {"query_language": "opensearch-lucene"}}
    )

    # When/Then the query is a Lucene query string on OCSF fields
    query = connector.translate(hunt_event["hunt"]["sigma_rule"], None)
    assert query.language == "opensearch-lucene"
    assert query.query.startswith("type_uid:100701 AND")
    assert "process.cmd_line:" in query.query


def test_translate_rejects_unknown_pipelines(connector_factory, hunt_event):
    # Given/When/Then an unknown pipeline is rejected with the supported ones
    with pytest.raises(HuntTranslationError, match="none, ocsf"):
        connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "ecs_windows")


def test_lucene_rules_are_joined_with_or(connector_factory):
    # Given a Lucene connector and a Sigma document with two rules
    connector = connector_factory(
        {"opensearch_ocsf_hunt": {"query_language": "opensearch-lucene"}}
    )

    # When/Then both queries are joined with OR
    query = connector.translate(TWO_RULES, None).query
    assert query.startswith("(type_uid:100701")
    assert ") OR (" in query


def test_ppl_rules_cannot_be_joined(connector_factory):
    # Given/When/Then two PPL queries cannot be combined
    with pytest.raises(HuntTranslationError, match="2 queries"):
        connector_factory().translate(TWO_RULES, None)


def test_strip_statement_end():
    # Given/When/Then trailing semicolons and blanks are removed
    assert strip_statement_end("source=x | head 5;  \n") == "source=x | head 5"


def test_execute_ppl_maps_rows(connector_factory, requests_mock):
    # Given a PPL answer with a nested OCSF object and its count
    requests_mock.post(
        PPL_URL,
        [
            {"json": ppl_answer(["time", "device"], [[EVENT_MS, {"hostname": "ws1"}]])},
            {"json": count_answer(1)},
        ],
    )

    # When the native query runs
    result = connector_factory().execute(
        NativeQuery(language="ppl", query="source=ocsf-*;"), WINDOW, HuntLimits()
    )

    # Then the rows become events with their OCSF time
    assert requests_mock.request_history[0].json()["query"].endswith("| head 1000")
    assert result.hits_count == 1
    assert result.truncated is False
    assert result.events[0].timestamp == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)
    assert result.events[0].fields["device.hostname"] == "ws1"


def test_execute_lucene_flags_truncation(connector_factory, requests_mock):
    # Given more Lucene matches than the cap
    requests_mock.post(SEARCH_URL, json=hits_answer([{"a": 1}], total=40))

    # When the native Lucene query runs with a cap of one
    result = connector_factory().execute(
        NativeQuery(language="opensearch-lucene", query="a:1"),
        WINDOW,
        HuntLimits(max_results=1),
    )

    # Then the total is kept and the result truncated
    assert (result.hits_count, result.truncated) == (40, True)
    assert result.events[0].timestamp is None


def test_execute_logs_partial_results(connector_factory):
    # Given a client returning partial results
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.lucene.return_value = SearchResult([{"a": 1}], 1, True)

    # When the query runs
    result = connector.execute(
        NativeQuery(language="opensearch-lucene", query="a:1"), WINDOW, HuntLimits()
    )

    # Then the result is truncated and the partial results logged
    assert result.truncated is True
    connector.logger.warning.assert_called_once_with(
        "[OPENSEARCH] Partial search results",
        {"language": "opensearch-lucene", "total": 1},
    )


def test_execute_requires_start():
    # Given/When/Then a connector that is not started has no client
    connector = OpenSearchOcsfHuntConnector(make_settings())
    with pytest.raises(RuntimeError):
        connector.execute(NativeQuery(language="ppl", query="x"), WINDOW, HuntLimits())


def test_process_message_reports_hits_and_sends_knowledge(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given OCSF events with a public IP, a private IP and a benign host
    requests_mock.post(
        PPL_URL,
        [
            {
                "json": ppl_answer(
                    ["time", "device.hostname", "dst_endpoint.ip", "raw_data"],
                    [
                        [EVENT_MS, "ws1", "8.8.8.8", "raw1"],
                        [EVENT_MS + 1000, "ws2", "10.0.0.1", "raw2"],
                        [EVENT_MS + 2000, "sccm01", "1.1.1.1", "raw3"],
                    ],
                )
            },
            {"json": count_answer(3)},
        ],
    )
    hunt_event["hunt"]["benign_patterns"] = ["/^sccm\\d+$/"]

    # When the hunt run is processed
    message = connector_factory().process_message(hunt_event)

    # Then the run is reported with the translated query and redacted evidence
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["query_language"] == "ppl"
    assert kwargs["translated_query"].startswith("source=ocsf-*")
    fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert "raw_data" not in fields and "device.hostname" in fields
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
    requests_mock.post(
        PPL_URL,
        [
            {"json": ppl_answer(["process.cmd_line"], [[command_line]] * 2)},
            {"json": count_answer(2)},
        ],
    )
    hunt_event["limits"]["evidence_max_value_length"] = 20

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the evidence holds the hash of the full value and a truncated preview
    evidence = helper.report_hunt_run.call_args.kwargs["evidence_sample"]
    assert evidence == [
        {
            "field": "process.cmd_line",
            "value_hash": hashlib.sha256(command_line.encode()).hexdigest(),
            "value_preview": command_line[:20],
            "count": 2,
        }
    ]


def test_process_message_preview(connector_factory, helper, requests_mock, hunt_event):
    # Given a preview run
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then the cluster is never queried
    assert requests_mock.call_count == 0
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["query_language"] == "ppl"


def test_process_message_executes_native_queries(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native Lucene query for OpenSearch
    requests_mock.post(SEARCH_URL, json=hits_answer([]))
    hunt_event["hunt"]["native_query"] = {
        "platform": "opensearch",
        "language": "opensearch-lucene",
        "query": "class_uid:4001 AND dst_endpoint.port:4444",
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the query runs verbatim and reports no hit
    must = requests_mock.last_request.json()["query"]["bool"]["must"]
    assert must == [
        {"query_string": {"query": "class_uid:4001 AND dst_endpoint.port:4444"}}
    ]
    assert helper.report_hunt_run.call_args.kwargs["hits_count"] == 0
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_rejects_unsupported_native_languages(
    connector_factory, helper, hunt_event
):
    # Given a native query in a language the connector does not run
    hunt_event["hunt"]["native_query"] = {
        "platform": "opensearch",
        "language": "sql",
        "query": "SELECT * FROM ocsf",
    }

    # When/Then the run fails with the supported languages
    with pytest.raises(HuntTranslationError, match="ppl, opensearch-lucene"):
        connector_factory().process_message(hunt_event)
    assert helper.report_hunt_run.call_args.args == ("run-1", "failed")


def test_process_message_reports_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a user without the PPL permission
    requests_mock.post(
        PPL_URL,
        status_code=403,
        json={
            "error": {
                "type": "security_exception",
                "reason": "no permissions for [cluster:admin/opensearch/ppl]",
            }
        },
    )

    # When/Then the run fails and is reported failed with the reason
    with pytest.raises(HuntExecutionError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "cluster:admin/opensearch/ppl" in kwargs["error"]
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_times_out(connector_factory, helper, hunt_event):
    # Given a query that never completes within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.ppl.side_effect = lambda *args: release.wait(5)
    hunt_event["limits"]["timeout_seconds"] = 1

    # When/Then the run times out and is reported failed
    try:
        with pytest.raises(HuntTimeoutError):
            connector.process_message(hunt_event)
    finally:
        release.set()
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "1 seconds" in kwargs["error"]


def test_start_registers_the_opensearch_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = OpenSearchOcsfHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered with both languages
    helper = helper_cls.return_value
    helper.register_hunt_platform.assert_called_once_with(
        platform="opensearch",
        languages=["ppl", "opensearch-lucene"],
        security_platform_name="OpenSearch",
        security_platform_type="SIEM",
        supports_preview=True,
        max_concurrent_runs=None,
    )
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )


def test_start_fails_fast_without_the_pycti_hunt_api():
    # Given a pycti without the hunt connector API
    connector = OpenSearchOcsfHuntConnector(make_settings())
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
