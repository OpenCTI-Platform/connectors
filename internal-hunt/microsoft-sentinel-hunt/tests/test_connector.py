import hashlib
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from conftest import QUERY_URL, make_settings, table
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from microsoft_sentinel_hunt import MicrosoftSentinelHuntConnector
from microsoft_sentinel_hunt.client import TokenRequestTransport
from microsoft_sentinel_hunt.connector import strip_statement_end

WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
MODULE = "microsoft_sentinel_hunt.connector"
COLUMNS = [
    ("TimeGenerated", "datetime"),
    ("Computer", "string"),
    ("DestinationIp", "string"),
    ("CommandLine", "string"),
    ("EventData", "string"),
    ("TenantId", "string"),
]


def _queries(requests_mock):
    return [request.json()["query"] for request in requests_mock.request_history]


def test_translate_with_the_configured_asim_pipeline(connector_factory, hunt_event):
    # Given/When a Sigma rule is translated with the default ASIM pipeline
    connector = connector_factory()
    query = connector.translate(hunt_event["hunt"]["sigma_rule"], None)

    # Then the KQL query targets the ASIM process parser
    assert query.language == "kql"
    assert query.query.startswith("imProcessCreate\n| where TargetProcessName")
    assert query.fields == ("TargetProcessName", "TargetProcessCommandLine")


@pytest.mark.parametrize(
    "pipeline, table_name",
    [
        pytest.param("microsoft_xdr", "DeviceProcessEvents", id="xdr"),
        pytest.param("azure_monitor", "SecurityEvent", id="azure_monitor"),
    ],
)
def test_translate_with_another_pipeline(
    connector_factory, hunt_event, pipeline, table_name
):
    # Given/When the hunt selects another pipeline
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], pipeline)

    # Then the query targets the tables of that pipeline
    assert query.query.startswith(table_name)


def test_translate_rejects_unknown_pipelines(connector_factory, hunt_event):
    # Given/When/Then an unknown pipeline is rejected with the supported ones
    with pytest.raises(HuntTranslationError, match="sentinel_asim"):
        connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "splunk_cim")


def test_combine_queries_with_union(connector_factory):
    # Given a connector
    connector = connector_factory()

    # When/Then several queries are combined with union
    assert connector.combine_queries(["A"]) == "A"
    assert connector.combine_queries(["A | where x", "B"]) == (
        "union (A | where x), (B)"
    )


def test_strip_statement_end():
    # Given/When/Then trailing semicolons and blanks are removed
    assert strip_statement_end("let x = 1;\nT | where a == x;  \n") == (
        "let x = 1;\nT | where a == x"
    )


def test_execute_caps_and_maps_rows(connector_factory, requests_mock):
    # Given a workspace returning fewer rows than the cap
    requests_mock.post(
        QUERY_URL,
        json=table(
            COLUMNS,
            [["2026-10-03T10:00:00Z", "ws1", "8.8.8.8", "cmd", "<xml/>", "t1"]],
        ),
    )

    # When the query is executed
    result = connector_factory().execute(
        NativeQuery(language="kql", query="SecurityEvent;"), WINDOW, HuntLimits()
    )

    # Then it is capped with take, and the total is the returned rows
    assert _queries(requests_mock) == ["SecurityEvent\n| take 1000"]
    assert result.hits_count == 1
    assert result.truncated is False
    assert result.events[0].timestamp == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)
    assert result.events[0].fields["Computer"] == "ws1"


def test_execute_counts_when_the_cap_is_reached(connector_factory, requests_mock):
    # Given a workspace with more matches than the cap
    requests_mock.post(
        QUERY_URL,
        [
            {"json": table([("Timestamp", "datetime")], [["2026-10-03T10:00:00Z"]])},
            {"json": table([("Count", "long")], [[42]])},
        ],
    )

    # When the query is executed with a cap of one result
    result = connector_factory().execute(
        NativeQuery(language="kql", query="DeviceEvents"),
        WINDOW,
        HuntLimits(max_results=1),
    )

    # Then the total comes from the count query
    assert _queries(requests_mock) == [
        "DeviceEvents\n| take 1",
        "DeviceEvents\n| count",
    ]
    assert result.hits_count == 42
    assert result.truncated is True
    assert result.events[0].timestamp == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "count_answer, expected",
    [
        pytest.param(table([("Count", "long")], []), 1, id="no_rows"),
        pytest.param(table([("Count", "string")], [["x"]]), 1, id="not_a_number"),
    ],
)
def test_execute_keeps_the_returned_rows_when_the_count_is_unusable(
    connector_factory, requests_mock, count_answer, expected
):
    # Given a count query without a usable answer
    requests_mock.post(
        QUERY_URL,
        [
            {"json": table([("Computer", "string")], [["ws1"]])},
            {"json": count_answer},
        ],
    )

    # When/Then the hit count is the number of returned rows
    result = connector_factory().execute(
        NativeQuery(language="kql", query="T"), WINDOW, HuntLimits(max_results=1)
    )
    assert result.hits_count == expected
    assert result.events[0].timestamp is None
    assert result.truncated is False


def test_execute_flags_partial_results(connector_factory, requests_mock):
    # Given a workspace returning a partial error
    answer = table([("Computer", "string")], [["ws1"]])
    answer["error"] = {"code": "PartialError", "message": "Query result truncated"}
    requests_mock.post(QUERY_URL, json=answer)
    connector = connector_factory()

    # When the query is executed
    result = connector.execute(
        NativeQuery(language="kql", query="T"), WINDOW, HuntLimits()
    )

    # Then the result is flagged truncated and the error logged
    assert result.truncated is True
    connector.logger.warning.assert_called_once_with(
        "[SENTINEL] Partial query results", {"error": "Query result truncated"}
    )


def test_execute_requires_start():
    # Given/When/Then a connector that is not started has no client
    connector = MicrosoftSentinelHuntConnector(make_settings())
    with pytest.raises(RuntimeError):
        connector.execute(NativeQuery(language="kql", query="T"), WINDOW, HuntLimits())


def test_build_credential_for_the_app_registration():
    # Given app registration settings
    connector = MicrosoftSentinelHuntConnector(make_settings())

    transport = TokenRequestTransport()

    # When the credential is built
    with patch(f"{MODULE}.ClientSecretCredential") as credential_cls:
        credential = connector.build_credential(transport)

    # Then it authenticates the app registration on the configured authority,
    # its token requests going through the deadline-bound transport
    assert credential is credential_cls.return_value
    credential_cls.assert_called_once_with(
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="secret-1",
        authority="login.microsoftonline.com",
        transport=transport,
    )


def test_build_credential_for_azure_credentials():
    # Given the DefaultAzureCredential method on Azure Government
    connector = MicrosoftSentinelHuntConnector(
        make_settings(
            {
                "microsoft_sentinel_hunt": {
                    "auth_type": "azure_credential",
                    "authority_host": "login.microsoftonline.us",
                }
            }
        )
    )

    transport = TokenRequestTransport()

    # When/Then DefaultAzureCredential is used on that authority with the deadline-bound transport
    with patch(f"{MODULE}.DefaultAzureCredential") as credential_cls:
        assert connector.build_credential(transport) is credential_cls.return_value
    credential_cls.assert_called_once_with(
        authority="login.microsoftonline.us", transport=transport
    )


def test_process_message_reports_hits_and_sends_knowledge(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given events with a public IP, a private IP and a benign host
    requests_mock.post(
        QUERY_URL,
        json=table(
            COLUMNS,
            [
                ["2026-10-03T10:00:00Z", "ws1", "8.8.8.8", "a", "<raw/>", "t"],
                ["2026-10-03T11:00:00Z", "ws2", "10.0.0.1", "b", "<raw/>", "t"],
                ["2026-10-03T12:00:00Z", "sccm01", "1.1.1.1", "c", "<raw/>", "t"],
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
    assert kwargs["query_language"] == "kql"
    assert kwargs["translated_query"].startswith("imProcessCreate")
    fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert "EventData" not in fields and "TenantId" not in fields
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
        QUERY_URL,
        json=table(
            [("TargetProcessCommandLine", "string")], [[command_line], [command_line]]
        ),
    )
    hunt_event["limits"]["evidence_max_value_length"] = 20

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the evidence holds the hash of the full value and a truncated preview
    evidence = helper.report_hunt_run.call_args.kwargs["evidence_sample"]
    assert evidence == [
        {
            "field": "TargetProcessCommandLine",
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

    # Then the workspace is never queried
    assert requests_mock.call_count == 0
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["translated_query"].startswith("imProcessCreate")


def test_process_message_executes_native_queries(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native KQL query for Microsoft Sentinel
    requests_mock.post(QUERY_URL, json=table([("Computer", "string")], []))
    hunt_event["hunt"]["native_query"] = {
        "platform": "microsoft-sentinel",
        "language": "kql",
        "query": "let bad = dynamic(['x']);\nDeviceProcessEvents | where FileName in (bad)",
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the query runs verbatim (capped) and reports no hit
    assert _queries(requests_mock)[0].endswith("in (bad)\n| take 100")
    assert helper.report_hunt_run.call_args.kwargs["hits_count"] == 0
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_reports_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given the app registration lacks access to the workspace
    requests_mock.post(
        QUERY_URL,
        status_code=403,
        json={"error": {"code": "InsufficientAccessError", "message": "No access"}},
    )

    # When/Then the run fails and is reported failed with the reason
    with pytest.raises(HuntExecutionError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "No access" in kwargs["error"]
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_times_out(connector_factory, helper, hunt_event):
    # Given a query that never completes within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.query.side_effect = lambda *args: release.wait(5)
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


def test_start_registers_the_sentinel_platform_and_listens(credential):
    # Given a pycti providing the hunt API
    connector = MicrosoftSentinelHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
        patch.object(
            MicrosoftSentinelHuntConnector, "build_credential", return_value=credential
        ),
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered and the hunt queue consumed
    helper = helper_cls.return_value
    helper.register_hunt_platform.assert_called_once_with(
        platform="microsoft-sentinel",
        languages=["kql"],
        security_platform_name="Microsoft Sentinel",
        security_platform_type="SIEM",
        supports_preview=True,
        max_concurrent_runs=None,
    )
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )
