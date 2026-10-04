import hashlib
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from conftest import ES_URL, esql_answer, hits_answer, make_settings
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from elastic_security_hunt import ElasticSecurityHuntConnector
from elastic_security_hunt.client import SearchResult
from elastic_security_hunt.connector import strip_statement_end

WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
ESQL_URL = f"{ES_URL}/_query/async"
INDICES = "logs-*,winlogbeat-*,filebeat-*,auditbeat-*,endgame-*"
SEARCH_URL = f"{ES_URL}/{INDICES}/_search"
EQL_URL = f"{ES_URL}/{INDICES}/_eql/search"
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


def test_translate_into_esql_over_the_configured_indices(connector_factory, hunt_event):
    # Given/When a Sigma rule is translated with the defaults
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], None)

    # Then it is an ES|QL query over the configured indices with ECS fields
    assert query.language == "esql"
    assert query.query.startswith(f"from {INDICES} metadata _id, _index, _version")
    assert "process.command_line" in query.query
    assert query.translated is True


def test_translate_into_esql_without_pipeline(connector_factory, hunt_event):
    # Given/When the hunt disables the pipeline
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "none")

    # Then the Sigma field names are kept, over the configured indices
    assert query.query.startswith(f"from {INDICES} ")
    assert "CommandLine" in query.query


@pytest.mark.parametrize(
    "language, prefix",
    [
        pytest.param("eql", "any where process.executable", id="eql"),
        pytest.param("lucene", "process.executable", id="lucene"),
    ],
)
def test_translate_into_the_configured_language(
    connector_factory, hunt_event, language, prefix
):
    # Given a connector translating into another language
    connector = connector_factory(
        {"elastic_security_hunt": {"query_language": language}}
    )

    # When/Then the query is in that language
    query = connector.translate(hunt_event["hunt"]["sigma_rule"], None)
    assert query.language == language
    assert query.query.startswith(prefix)


def test_translate_rejects_unknown_pipelines(connector_factory, hunt_event):
    # Given/When/Then an unknown pipeline is rejected with the supported ones
    with pytest.raises(HuntTranslationError, match="ecs_windows"):
        connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "splunk_cim")


def test_lucene_rules_are_joined_with_or(connector_factory):
    # Given a Lucene connector and a Sigma document with two rules
    connector = connector_factory(
        {"elastic_security_hunt": {"query_language": "lucene"}}
    )

    # When/Then both queries are joined with OR
    query = connector.translate(TWO_RULES, None).query
    assert query.startswith("(process.executable")
    assert ") OR (" in query


def test_esql_rules_cannot_be_joined(connector_factory):
    # Given/When/Then two ES|QL queries cannot be combined
    with pytest.raises(HuntTranslationError, match="2 queries"):
        connector_factory().translate(TWO_RULES, None)


def test_strip_statement_end():
    # Given/When/Then trailing semicolons and blanks are removed
    assert strip_statement_end("from x | limit 5;  \n") == "from x | limit 5"


def test_execute_esql_maps_rows(connector_factory, requests_mock):
    # Given an ES|QL answer
    requests_mock.post(
        ESQL_URL,
        json=esql_answer(
            ["@timestamp", "host.name"], [["2026-10-03T10:00:00.000Z", "ws1"]]
        ),
    )

    # When the native query runs
    result = connector_factory().execute(
        NativeQuery(language="esql", query="from logs-* | where true;"),
        WINDOW,
        HuntLimits(),
    )

    # Then the rows become events with their timestamp
    assert requests_mock.last_request.json()["query"] == (
        "from logs-* | where true\n| limit 1000"
    )
    assert result.hits_count == 1
    assert result.events[0].timestamp == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)
    assert result.events[0].fields["host.name"] == "ws1"


def test_execute_eql_over_the_indices(connector_factory, requests_mock):
    # Given an EQL answer
    requests_mock.post(
        EQL_URL,
        json={
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "events": [
                    {"_source": {"@timestamp": "2026-10-03T11:00:00Z", "a": {"b": 1}}}
                ],
            }
        },
    )

    # When the native EQL query runs
    result = connector_factory().execute(
        NativeQuery(language="eql", query="process where true"), WINDOW, HuntLimits()
    )

    # Then the nested source is flattened
    assert result.events[0].fields["a.b"] == 1
    assert result.truncated is False


def test_execute_lucene_flags_truncation(connector_factory, requests_mock):
    # Given more Lucene matches than the cap
    requests_mock.post(SEARCH_URL, json=hits_answer([{"a": 1}], total=40))

    # When the native Lucene query runs with a cap of one
    result = connector_factory().execute(
        NativeQuery(language="lucene", query="a:1"), WINDOW, HuntLimits(max_results=1)
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
        NativeQuery(language="lucene", query="a:1"), WINDOW, HuntLimits()
    )

    # Then the result is truncated and the partial results logged
    assert result.truncated is True
    connector.logger.warning.assert_called_once_with(
        "[ELASTIC] Partial search results", {"language": "lucene", "total": 1}
    )


def test_execute_requires_start():
    # Given/When/Then a connector that is not started has no client
    connector = ElasticSecurityHuntConnector(make_settings())
    with pytest.raises(RuntimeError):
        connector.execute(NativeQuery(language="esql", query="x"), WINDOW, HuntLimits())


def test_on_timeout_cancels_the_search_of_the_run(connector_factory):
    # Given a started connector
    connector = connector_factory()
    connector.client = MagicMock()
    query = NativeQuery(language="esql", query="from x")

    # When the run times out
    connector.on_timeout(query)

    # Then the search of that query is cancelled
    connector.client.cancel.assert_called_once_with(id(query))


def test_on_timeout_without_client():
    # Given/When/Then a connector that is not started has nothing to cancel
    ElasticSecurityHuntConnector(make_settings()).on_timeout(
        NativeQuery(language="esql", query="x")
    )


def test_process_message_reports_hits_and_sends_knowledge(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given events with a public IP, a private IP and a benign host
    requests_mock.post(
        ESQL_URL,
        json=esql_answer(
            ["@timestamp", "host.name", "destination.ip", "event.original", "_id"],
            [
                ["2026-10-03T10:00:00Z", "ws1", "8.8.8.8", "raw1", "id1"],
                ["2026-10-03T11:00:00Z", "ws2", "10.0.0.1", "raw2", "id2"],
                ["2026-10-03T12:00:00Z", "sccm01", "1.1.1.1", "raw3", "id3"],
            ],
        ),
    )
    hunt_event["hunt"]["benign_patterns"] = ["/^sccm\\d+$/"]

    # When the hunt run is processed
    message = connector_factory().process_message(hunt_event)

    # Then the run is reported with the translated query and redacted evidence
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["query_language"] == "esql"
    assert kwargs["translated_query"].startswith(f"from {INDICES}")
    fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert "event.original" not in fields and "_id" not in fields
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
        ESQL_URL,
        json=esql_answer(["process.command_line"], [[command_line], [command_line]]),
    )
    hunt_event["limits"]["evidence_max_value_length"] = 20

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the evidence holds the hash of the full value and a truncated preview
    evidence = helper.report_hunt_run.call_args.kwargs["evidence_sample"]
    assert evidence == [
        {
            "field": "process.command_line",
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
    assert kwargs["query_language"] == "esql"


def test_process_message_executes_native_queries(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native EQL query for Elastic Security
    requests_mock.post(EQL_URL, json={"hits": {"events": []}})
    hunt_event["hunt"]["native_query"] = {
        "platform": "elastic-security",
        "language": "eql",
        "query": "sequence by host.id [process where true] [network where true]",
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the query runs verbatim and reports no hit
    assert requests_mock.last_request.json()["query"].startswith("sequence by host.id")
    assert helper.report_hunt_run.call_args.kwargs["hits_count"] == 0
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_rejects_unsupported_native_languages(
    connector_factory, helper, hunt_event
):
    # Given a native query in a language the connector does not run
    hunt_event["hunt"]["native_query"] = {
        "platform": "elastic-security",
        "language": "kql",
        "query": "process.name : x",
    }

    # When/Then the run fails with the supported languages
    with pytest.raises(HuntTranslationError, match="esql, eql, lucene"):
        connector_factory().process_message(hunt_event)
    assert helper.report_hunt_run.call_args.args == ("run-1", "failed")


def test_process_message_reports_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given an API key without the read privilege
    requests_mock.post(
        ESQL_URL,
        status_code=403,
        json={"error": {"type": "security_exception", "reason": "unauthorized"}},
    )

    # When/Then the run fails and is reported failed with the reason
    with pytest.raises(HuntExecutionError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "unauthorized" in kwargs["error"]
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_times_out(connector_factory, helper, hunt_event):
    # Given a query that never completes within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.esql.side_effect = lambda *args: release.wait(5)
    hunt_event["limits"]["timeout_seconds"] = 1

    # When/Then the run times out, the search is cancelled and the run reported as a timeout
    try:
        with pytest.raises(HuntTimeoutError):
            connector.process_message(hunt_event)
    finally:
        release.set()
    connector.client.cancel.assert_called_once()
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "timeout")
    assert "1 seconds" in kwargs["error"]


def test_start_registers_the_elastic_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = ElasticSecurityHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered with the three languages
    helper = helper_cls.return_value
    helper.register_hunt_platform.assert_called_once_with(
        platform="elastic-security",
        languages=["esql", "eql", "lucene"],
        security_platform_name="Elastic Security",
        security_platform_type="SIEM",
        supports_preview=True,
        max_concurrent_runs=None,
        supports_indicators=False,
        required_permissions=[
            {"name": name, "purpose": purpose}
            for name, purpose in ElasticSecurityHuntConnector.required_permissions
        ],
        documentation_url=ElasticSecurityHuntConnector.documentation_url,
    )
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )


def test_start_fails_fast_without_the_pycti_hunt_api():
    # Given a pycti without the hunt connector API
    connector = ElasticSecurityHuntConnector(make_settings())
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
