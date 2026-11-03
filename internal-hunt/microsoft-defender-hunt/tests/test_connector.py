import hashlib
import threading
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from conftest import HUNTING_URL, answer, hunting_queries, make_settings
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from microsoft_defender_hunt import MicrosoftDefenderHuntConnector
from microsoft_defender_hunt.connector import event_id, strip_statement_end

WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
WINDOW_FILTER = (
    "| where Timestamp between (datetime(2026-10-03T00:00:00.000Z) .. "
    "datetime(2026-10-04T00:00:00.000Z))"
)
SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
COLUMNS = [
    ("Timestamp", "DateTime"),
    ("DeviceId", "String"),
    ("DeviceName", "String"),
    ("ReportId", "Int64"),
    ("AccountName", "String"),
    ("InitiatingProcessAccountName", "String"),
    ("InitiatingProcessFolderPath", "String"),
    ("RemoteIP", "String"),
    ("ProcessCommandLine", "String"),
    ("AdditionalFields", "Dynamic"),
    ("TenantId", "String"),
]


def _row(timestamp, device, name, report, remote_ip, command="cmd"):
    return [
        timestamp,
        device,
        name,
        report,
        "alice",
        "system",
        "c:\\windows\\system32\\cmd.exe",
        remote_ip,
        command,
        '{"raw": 1}',
        "t1",
    ]


def test_translate_with_the_microsoft_xdr_pipeline(connector_factory, hunt_event):
    # Given/When a Sigma rule is translated with the default pipeline
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], None)

    # Then the KQL query targets the Defender XDR process table
    assert query.language == "kql"
    assert query.translated is True
    assert query.query.startswith("DeviceProcessEvents\n| where ")
    assert 'FolderPath endswith "\\\\powershell.exe"' in query.query
    assert query.fields == ("FolderPath", "ProcessCommandLine")


def test_translate_rejects_unknown_pipelines(connector_factory, hunt_event):
    # Given/When/Then an unknown pipeline is rejected with the supported ones
    with pytest.raises(HuntTranslationError, match="microsoft_xdr"):
        connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "sentinel_asim")


def test_translate_rejects_categories_without_table(connector_factory):
    # Given/When/Then a DNS rule (no Defender XDR table in the pipeline) does not translate
    rule = (
        "title: DNS\nlogsource:\n  category: dns_query\n  product: windows\n"
        "detection:\n  selection:\n    QueryName: evil.example\n  condition: selection\n"
    )
    with pytest.raises(HuntTranslationError):
        connector_factory().translate(rule, None)


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


@pytest.mark.parametrize(
    "row, expected",
    [
        pytest.param(
            {"ReportId": 7, "DeviceId": "d1", "Timestamp": "2026-10-03T10:00:00Z"},
            "d1|7|2026-10-03T10:00:00Z",
            id="device",
        ),
        pytest.param(
            {
                "ReportId": "r1",
                "NetworkMessageId": "m1",
                "RecipientEmailAddress": "a@b.example",
                "Timestamp": "t",
            },
            "m1|a@b.example|r1|t",
            id="email",
        ),
        pytest.param({"ReportId": 3}, "3|", id="report_only"),
        pytest.param(
            {"ReportId_string": None, "ReportId_long": 9, "DeviceId": "d1"},
            "d1|9|",
            id="union_of_types",
        ),
        pytest.param({"DeviceId": "d1", "Timestamp": "t"}, None, id="no_report"),
        pytest.param({"ReportId": " ", "Timestamp": "t"}, None, id="blank_report"),
    ],
)
def test_event_id_scopes_the_report_id(row, expected):
    # Given/When/Then the id of an event is its report id within its device or
    # message and recipient, and its time
    assert event_id(row) == expected


def test_execute_runs_translated_rules_over_the_window(
    connector_factory, requests_mock
):
    # Given advanced hunting returning fewer rows than the cap
    requests_mock.post(
        HUNTING_URL,
        json=answer(
            COLUMNS,
            [_row("2026-10-03T10:00:00.1234567Z", "dev-1", "ws1", 42, "8.8.8.8")],
        ),
    )

    # When a translated query is executed
    result = connector_factory().execute(
        NativeQuery(language="kql", query="DeviceProcessEvents;", translated=True),
        WINDOW,
        HuntLimits(),
    )

    # Then it is filtered on the window, capped with take, sent with the window
    # as its timespan, and the total is the returned rows
    assert hunting_queries(requests_mock) == [
        f"DeviceProcessEvents\n{WINDOW_FILTER}\n| take 1000"
    ]
    assert requests_mock.last_request.json()["Timespan"] == (
        "2026-10-03T00:00:00.000Z/2026-10-04T00:00:00.000Z"
    )
    assert (result.hits_count, result.truncated) == (1, False)
    event = result.events[0]
    assert event.timestamp == datetime(2026, 10, 3, 10, 0, 0, 123456, tzinfo=UTC)
    assert event.fields["DeviceName"] == "ws1"
    assert event.fields["HuntEventId"] == "dev-1|42|2026-10-03T10:00:00.1234567Z"


def test_execute_runs_native_queries_verbatim(connector_factory, requests_mock):
    # Given a native query, which may not hold a Timestamp column
    requests_mock.post(HUNTING_URL, json=answer([("Count", "Int64")], [[3]]))

    # When it is executed
    result = connector_factory().execute(
        NativeQuery(language="kql", query="DeviceInfo | summarize count()"),
        WINDOW,
        HuntLimits(),
    )

    # Then the window is its timespan only, and a row without time has none
    assert hunting_queries(requests_mock) == [
        "DeviceInfo | summarize count()\n| take 1000"
    ]
    assert result.events[0].timestamp is None
    assert result.queries_count == 1


def test_execute_counts_when_the_cap_is_reached(connector_factory, requests_mock):
    # Given a tenant with more matches than the cap
    requests_mock.post(
        HUNTING_URL,
        [
            {"json": answer([("Timestamp", "DateTime")], [["2026-10-03T10:00:00Z"]])},
            {"json": answer([("Count", "Int64")], [[42]])},
        ],
    )

    # When the query is executed with a cap of one result
    result = connector_factory().execute(
        NativeQuery(language="kql", query="DeviceEvents"),
        WINDOW,
        HuntLimits(max_results=1),
    )

    # Then the total comes from the count query, and the result is truncated
    assert hunting_queries(requests_mock) == [
        "DeviceEvents\n| take 1",
        "DeviceEvents\n| count",
    ]
    assert (result.hits_count, result.truncated) == (42, True)
    assert result.queries_count == 2


def test_execute_caps_at_10000_rows(connector_factory, requests_mock):
    # Given a run allowing more results than the connector reads from one query
    requests_mock.post(
        HUNTING_URL,
        [
            {"json": answer([("x", "Int32")], [[index] for index in range(10_000)])},
            {"json": answer([("Count", "Int64")], [[25_000]])},
        ],
    )

    # When the query is executed
    result = connector_factory().execute(
        NativeQuery(language="kql", query="DeviceEvents"),
        WINDOW,
        HuntLimits(max_results=50_000),
    )

    # Then it is capped at 10,000 rows and flagged truncated
    assert hunting_queries(requests_mock)[0] == "DeviceEvents\n| take 10000"
    assert (len(result.events), result.hits_count, result.truncated) == (
        10_000,
        25_000,
        True,
    )


@pytest.mark.parametrize(
    "count_answer",
    [
        pytest.param(answer([("Count", "Int64")], []), id="no_rows"),
        pytest.param(answer([("Count", "String")], [["x"]]), id="not_a_number"),
        pytest.param(answer([("Count", "Int64")], [[0]]), id="below_the_page"),
        pytest.param(answer([("Count", "Boolean")], [[True]]), id="boolean"),
    ],
)
def test_execute_keeps_the_returned_rows_when_the_count_is_unusable(
    connector_factory, requests_mock, count_answer
):
    # Given a count query without a usable answer
    requests_mock.post(
        HUNTING_URL,
        [{"json": answer([("x", "Int32")], [[1]])}, {"json": count_answer}],
    )

    # When/Then the hit count is the number of returned rows, a lower bound of
    # a partial result
    result = connector_factory().execute(
        NativeQuery(language="kql", query="T"), WINDOW, HuntLimits(max_results=1)
    )
    assert (result.hits_count, result.truncated) == (1, True)


@pytest.mark.parametrize("count", [1, "1"])
def test_execute_reports_a_complete_count_equal_to_the_cap(
    connector_factory, requests_mock, count
):
    # Given a full page whose count query confirms there is nothing more
    requests_mock.post(
        HUNTING_URL,
        [
            {"json": answer([("x", "Int32")], [[1]])},
            {"json": answer([("Count", "Int64")], [[count]])},
        ],
    )

    # When/Then the result is complete
    result = connector_factory().execute(
        NativeQuery(language="kql", query="T"), WINDOW, HuntLimits(max_results=1)
    )
    assert (result.hits_count, result.truncated) == (1, False)


def test_execute_requires_start():
    # Given/When/Then a connector that is not started has no client
    connector = MicrosoftDefenderHuntConnector(make_settings())
    with pytest.raises(RuntimeError):
        connector.execute(NativeQuery(language="kql", query="T"), WINDOW, HuntLimits())


def test_post_init_targets_the_configured_cloud():
    # Given the URLs of a national cloud
    connector = MicrosoftDefenderHuntConnector(
        make_settings(
            {
                "microsoft_defender_hunt": {
                    "login_url": "https://login.microsoftonline.us",
                    "graph_url": "https://graph.microsoft.us/",
                }
            }
        )
    )

    # When the clients are created
    connector.post_init()

    # Then the tokens are requested for that Microsoft Graph, on that login URL
    tokens = connector.client.tokens
    assert tokens._form["scope"] == "https://graph.microsoft.us/.default"
    assert tokens._build_url(tokens._path) == (
        "https://login.microsoftonline.us/tenant-1/oauth2/v2.0/token"
    )


def test_process_message_reports_hits_and_sends_knowledge(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given events with a public IP, a private IP and a benign host
    requests_mock.post(
        HUNTING_URL,
        json=answer(
            COLUMNS,
            [
                _row("2026-10-03T10:00:00Z", "dev-1", "ws1", 1, "8.8.8.8"),
                _row("2026-10-03T11:00:00Z", "dev-2", "ws2", 2, "10.0.0.1"),
                _row("2026-10-03T12:00:00Z", "dev-3", "sccm01", 3, "1.1.1.1"),
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
    assert kwargs["translated_query"].startswith("DeviceProcessEvents")
    assert WINDOW_FILTER in hunting_queries(requests_mock)[0]
    fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert not fields & {"AdditionalFields", "TenantId", "ReportId", "HuntEventId"}
    for item in kwargs["evidence_sample"]:
        assert len(item["value_hash"]) == 64
    assert "2 hit(s)" in message
    # And each hit names its machine, user, process and event
    assert [
        (hit["host"], hit["user"], hit["process"], hit["event_id"])
        for hit in kwargs["hits_sample"]
    ] == [
        (
            "ws1",
            "alice",
            "c:\\windows\\system32\\cmd.exe",
            "dev-1|1|2026-10-03T10:00:00Z",
        ),
        (
            "ws2",
            "alice",
            "c:\\windows\\system32\\cmd.exe",
            "dev-2|2|2026-10-03T11:00:00Z",
        ),
    ]
    assert len(set(kwargs["hit_keys"])) == kwargs["hits_count"]
    # And the observed public IP only, without sighting
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert "sighting" not in {obj["type"] for obj in sent}
    assert [obj["value"] for obj in sent if obj["type"] == "ipv4-addr"] == ["8.8.8.8"]


def test_hit_keys_are_stable_across_runs(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given the same event returned by two runs, its command line truncated differently
    rows = [_row("2026-10-03T10:00:00Z", "dev-1", "ws1", 1, "8.8.8.8")]
    requests_mock.post(HUNTING_URL, json=answer(COLUMNS, rows))
    connector = connector_factory()

    # When both runs are processed
    connector.process_message(hunt_event)
    first = helper.report_hunt_run.call_args.kwargs["hit_keys"]
    hunt_event["limits"]["evidence_max_value_length"] = 5
    connector.process_message(hunt_event)

    # Then the hit has the same key, derived from its event id
    assert helper.report_hunt_run.call_args.kwargs["hit_keys"] == first


def test_process_message_evidence_is_hashed_and_truncated(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a long command line
    command_line = "powershell -enc " + "B" * 300
    requests_mock.post(
        HUNTING_URL,
        json=answer(
            [("ProcessCommandLine", "String")], [[command_line], [command_line]]
        ),
    )
    hunt_event["limits"]["evidence_max_value_length"] = 20

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the evidence holds the hash of the full value and a truncated preview
    evidence = helper.report_hunt_run.call_args.kwargs["evidence_sample"]
    assert evidence == [
        {
            "field": "ProcessCommandLine",
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

    # Then advanced hunting is never queried
    assert hunting_queries(requests_mock) == []
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["translated_query"].startswith("DeviceProcessEvents")


def test_process_message_executes_native_queries(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native KQL query for Microsoft Defender XDR
    requests_mock.post(
        HUNTING_URL,
        json=answer(
            [("DeviceName", "String"), ("RemoteUrl", "String"), ("ReportId", "Int64")],
            [["ws1", "https://evil.example/", 5]],
        ),
    )
    hunt_event["hunt"]["native_query"] = {
        "platform": "microsoft-defender",
        "language": "kql",
        "query": 'let bad = dynamic(["evil.example"]);\n'
        "DeviceNetworkEvents | where RemoteUrl has_any (bad)",
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the query runs verbatim (capped, without the Sigma time filter)
    [query] = hunting_queries(requests_mock)
    assert query.endswith("has_any (bad)\n| take 100")
    assert "Timestamp between" not in query
    # And each hit names the columns the query references
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["hits_count"] == 1
    assert [item["field"] for item in kwargs["hits_sample"][0]["matched"]] == [
        "RemoteUrl"
    ]


def test_process_message_reports_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given the app registration lacks the advanced hunting permission
    requests_mock.post(
        HUNTING_URL,
        status_code=403,
        json={"error": {"code": "Forbidden", "message": "Missing role permissions"}},
    )

    # When/Then the run fails and is reported failed with the reason
    with pytest.raises(HuntExecutionError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "ThreatHunting.Read.All" in kwargs["error"]
    assert "Missing role permissions" in kwargs["error"]
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_times_out(connector_factory, helper, hunt_event):
    # Given a query that never completes within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.run_query.side_effect = lambda *args: release.wait(5)
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


def test_start_registers_the_defender_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = MicrosoftDefenderHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered with indicator support, and the hunt queue consumed
    helper = helper_cls.return_value
    helper.register_hunt_platform.assert_called_once_with(
        platform="microsoft-defender",
        languages=["kql"],
        security_platform_name="Microsoft Defender XDR",
        security_platform_type="XDR",
        supports_preview=True,
        max_concurrent_runs=2,
        supports_indicators=True,
        required_permissions=[
            {"name": "ThreatHunting.Read.All", "purpose": purpose}
            for _, purpose in MicrosoftDefenderHuntConnector.required_permissions
        ],
        documentation_url=MicrosoftDefenderHuntConnector.documentation_url,
    )
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )
