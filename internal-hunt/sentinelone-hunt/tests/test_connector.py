import hashlib
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from conftest import (
    FORWARD_TAG,
    QUERIES_URL,
    done,
    launched_queries,
    make_settings,
    mock_query,
)
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from sentinelone_hunt import SentinelOneHuntConnector
from sentinelone_hunt.client import QueryResult
from sentinelone_hunt.connector import (
    EDR_FILTER,
    RESULT_COLUMNS,
    event_time,
    strip_statement_end,
)

WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
TEN_AM = datetime(2026, 10, 3, 10, tzinfo=timezone.utc)
TEN_AM_NS = 1791021600000000000


def test_translate_scopes_the_rule_to_the_edr_telemetry(connector_factory, hunt_event):
    # Given/When a Sigma rule is translated with the default settings
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], None)

    # Then the PowerQuery starts with the EDR filter, keeps the rule conditions
    # and names the columns of the hits and of the detection
    assert query.language == "powerquery"
    assert query.query.startswith(f"{EDR_FILTER} and (event.type in:anycase")
    filter_part, columns = query.query.split(" | columns ")
    assert "tgt.process.image.path ends_with" in filter_part
    names = columns.split(", ")
    assert names[: len(RESULT_COLUMNS)] == list(RESULT_COLUMNS)
    assert "tgt.process.cmdline" in names
    assert len(names) == len(set(names))


def test_translate_without_the_edr_filter(connector_factory, hunt_event):
    # Given a connector searching the whole Data Lake
    connector = connector_factory({"sentinelone_hunt": {"edr_only": False}})

    # When/Then the rule is not restricted to the EDR telemetry
    query = connector.translate(hunt_event["hunt"]["sigma_rule"], None)
    assert query.query.startswith("event.type in:anycase")


def test_translate_without_pipeline_keeps_the_rule_fields(
    connector_factory, hunt_event
):
    # Given/When the hunt selects no pipeline
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "none")

    # Then the Sigma field names are used as written
    assert "Image ends_with" in query.query
    assert "endpoint.os" not in query.query


def test_translate_rejects_unknown_pipelines(connector_factory, hunt_event):
    # Given/When/Then an unknown pipeline is rejected with the supported ones
    with pytest.raises(HuntTranslationError, match="sentinelone_pq"):
        connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "ecs_windows")


def test_combine_queries_with_or(connector_factory):
    # Given/When/Then several queries are combined with or
    assert connector_factory().combine_queries(["a=1", "b=2"]) == "(a=1) or (b=2)"


def test_strip_statement_end():
    # Given/When/Then trailing pipes and blanks are removed
    assert strip_statement_end(" event.type = 'x' | \n") == "event.type = 'x'"


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(TEN_AM_NS, id="nanoseconds"),
        pytest.param(str(TEN_AM_NS), id="nanoseconds_string"),
        pytest.param(TEN_AM_NS // 1000, id="microseconds"),
        pytest.param(TEN_AM_NS // 1000000, id="milliseconds"),
        pytest.param(TEN_AM_NS // 1000000000, id="seconds"),
        pytest.param("2026-10-03T10:00:00Z", id="iso"),
    ],
)
def test_event_time(value):
    # Given/When/Then every time unit SentinelOne may return is read
    assert event_time(value) == TEN_AM


@pytest.mark.parametrize("value", [None, True, "n/a"])
def test_event_time_without_time(value):
    # Given/When/Then a missing or invalid time is unknown
    assert event_time(value) is None


def test_execute_caps_and_maps_events(connector_factory, requests_mock):
    # Given a query returning fewer rows than the cap
    mock_query(
        requests_mock,
        done(
            ["timestamp", "endpoint.name", "tgt.process.user"],
            [[TEN_AM_NS, "ws1", None]],
        ),
    )

    # When a native query runs
    result = connector_factory().execute(
        NativeQuery(language="powerquery", query="event.type = 'DNS Resolved' |"),
        WINDOW,
        HuntLimits(),
    )

    # Then it is capped with limit and its fields are not checked
    assert launched_queries(requests_mock) == [
        "event.type = 'DNS Resolved' | limit 1000"
    ]
    assert "scheme" not in requests_mock.request_history[0].json()
    # And the events keep their time and drop empty columns
    assert (result.hits_count, result.queries_count, result.truncated) == (
        1,
        1,
        False,
    )
    assert result.events[0].timestamp == TEN_AM
    assert result.events[0].fields == {"timestamp": TEN_AM_NS, "endpoint.name": "ws1"}


def test_execute_checks_the_fields_of_edr_queries(connector_factory, requests_mock):
    # Given a query starting with the EDR filter
    mock_query(requests_mock, done([], []))

    # When it runs
    connector_factory().execute(
        NativeQuery(language="powerquery", query=f"{EDR_FILTER} and (x = 1)"),
        WINDOW,
        HuntLimits(),
    )

    # Then SentinelOne checks its field names against the EDR schema
    assert requests_mock.request_history[0].json()["scheme"] == "edr"


def test_execute_counts_when_the_cap_is_reached(connector_factory, requests_mock):
    # Given more events than the cap
    tag = {"X-Dataset-Query-Forward-Tag": FORWARD_TAG}
    requests_mock.post(
        QUERIES_URL,
        [
            {"json": done(["timestamp"], [[TEN_AM_NS]], query_id="q1"), "headers": tag},
            {
                "json": done(["opencti_hit_count"], [[42]], query_id="q2"),
                "headers": tag,
            },
        ],
    )
    requests_mock.delete(f"{QUERIES_URL}/q1", status_code=204)
    requests_mock.delete(f"{QUERIES_URL}/q2", status_code=204)

    # When the query runs with a cap of one event
    result = connector_factory().execute(
        NativeQuery(language="powerquery", query="q"),
        WINDOW,
        HuntLimits(max_results=1),
    )

    # Then the total comes from the count query
    assert launched_queries(requests_mock) == [
        "q | limit 1",
        "q | group opencti_hit_count = count()",
    ]
    assert (result.hits_count, result.truncated, result.queries_count) == (42, True, 2)


@pytest.mark.parametrize(
    "count_rows, expected, truncated",
    [
        pytest.param([{"opencti_hit_count": 7}], 7, True, id="number"),
        pytest.param([{"opencti_hit_count": "7"}], 7, True, id="string"),
        pytest.param([{"opencti_hit_count": 1}], 1, False, id="exactly_the_cap"),
        pytest.param([], 1, True, id="no_row"),
        pytest.param([{"opencti_hit_count": "n/a"}], 1, True, id="not_a_number"),
        pytest.param([{"opencti_hit_count": True}], 1, True, id="boolean"),
        pytest.param([{"opencti_hit_count": 0}], 1, True, id="below_the_page"),
    ],
)
def test_execute_reads_the_count(connector_factory, count_rows, expected, truncated):
    # Given a client whose count query answers in various shapes
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.query.side_effect = [
        QueryResult([{"a": 1}], None),
        QueryResult(count_rows, None),
    ]

    # When the cap-filled query runs
    result = connector.execute(
        NativeQuery(language="powerquery", query="q"),
        WINDOW,
        HuntLimits(max_results=1),
    )

    # Then the hit count is read when usable, and an unusable count leaves the
    # page size as a lower bound of a partial result
    assert (result.hits_count, result.truncated) == (expected, truncated)
    assert result.events[0].timestamp is None


def test_execute_requires_start():
    # Given/When/Then a connector that is not started has no client
    connector = SentinelOneHuntConnector(make_settings())
    with pytest.raises(RuntimeError):
        connector.execute(
            NativeQuery(language="powerquery", query="q"), WINDOW, HuntLimits()
        )


def test_on_timeout_cancels_the_query(connector_factory):
    # Given a started connector
    connector = connector_factory()
    connector.client = MagicMock()
    query = NativeQuery(language="powerquery", query="q")

    # When/Then the query is cancelled
    connector.on_timeout(query)
    connector.client.cancel.assert_called_once_with(id(query))


def test_on_timeout_without_client():
    # Given/When/Then a connector that is not started has nothing to cancel
    SentinelOneHuntConnector(make_settings()).on_timeout(
        NativeQuery(language="powerquery", query="q")
    )


def test_process_message_reports_hits_and_sends_knowledge(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given events with a public IP, a private IP and a benign host
    columns = [
        "timestamp",
        "event.id",
        "agent.uuid",
        "endpoint.name",
        "dst.ip.address",
        "message",
    ]
    mock_query(
        requests_mock,
        done(
            columns,
            [
                [TEN_AM_NS, "e1", "a1", "ws1", "8.8.8.8", "raw"],
                [TEN_AM_NS, "e2", "a2", "ws2", "10.0.0.1", "raw"],
                [TEN_AM_NS, "e3", "a3", "sccm01", "1.1.1.1", "raw"],
            ],
        ),
    )
    hunt_event["hunt"]["benign_patterns"] = ["/^sccm\\d+$/"]

    # When the hunt run is processed
    message = connector_factory().process_message(hunt_event)

    # Then the translated rule runs on the EDR telemetry with its fields checked
    launch = requests_mock.request_history[0].json()
    assert launch["pq"]["query"].startswith(EDR_FILTER)
    assert launch["pq"]["query"].endswith(" | limit 100")
    assert launch["scheme"] == "edr"
    # And the run is reported with the translated query and redacted evidence
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["query_language"] == "powerquery"
    assert kwargs["translated_query"].startswith(EDR_FILTER)
    fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert not fields & {"message", "event.id", "agent.uuid"}
    for item in kwargs["evidence_sample"]:
        assert len(item["value_hash"]) == 64
    assert "2 hit(s)" in message
    # And each hit is keyed by its event id, on its endpoint
    assert {(hit["event_id"], hit["host"]) for hit in kwargs["hits_sample"]} == {
        ("e1", "ws1"),
        ("e2", "ws2"),
    }
    # And the observed public IP only, without sighting: OpenCTI keeps one per
    # technique or indicator and platform, from the hit keys of the runs
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert "sighting" not in {obj["type"] for obj in sent}
    assert len(kwargs["hit_keys"]) == kwargs["hits_count"]
    assert [obj["value"] for obj in sent if obj["type"] == "ipv4-addr"] == ["8.8.8.8"]


def test_process_message_evidence_is_hashed_and_truncated(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a long command line
    command_line = "powershell -enc " + "B" * 300
    mock_query(
        requests_mock,
        done(["src.process.cmdline"], [[command_line], [command_line]]),
    )
    hunt_event["limits"]["evidence_max_value_length"] = 20

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the evidence holds the hash of the full value and a truncated preview
    evidence = helper.report_hunt_run.call_args.kwargs["evidence_sample"]
    assert evidence == [
        {
            "field": "src.process.cmdline",
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

    # Then SentinelOne is never queried
    assert requests_mock.call_count == 0
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["query_language"] == "powerquery"
    assert kwargs["translated_query"].startswith(EDR_FILTER)


def test_process_message_executes_native_queries(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native PowerQuery for SentinelOne
    mock_query(requests_mock, done([], []))
    hunt_event["hunt"]["native_query"] = {
        "platform": "sentinelone",
        "language": "powerquery",
        "query": "event.type = 'DNS Resolved' | group n = count() by event.dns.request",
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the query runs verbatim (capped) and reports no hit
    assert launched_queries(requests_mock) == [
        "event.type = 'DNS Resolved' | group n = count() by event.dns.request"
        " | limit 100"
    ]
    assert helper.report_hunt_run.call_args.kwargs["hits_count"] == 0
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_reports_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a service user without access to the account
    requests_mock.post(
        QUERIES_URL,
        status_code=403,
        json={"errors": [{"detail": "Not allowed to access requested resource"}]},
    )

    # When/Then the run fails and is reported failed with what to grant
    with pytest.raises(HuntExecutionError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "SENTINELONE_HUNT_ACCOUNT_IDS" in kwargs["error"]
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_times_out(connector_factory, helper, hunt_event):
    # Given a query that never completes within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.query.side_effect = lambda *args: release.wait(5)
    hunt_event["limits"]["timeout_seconds"] = 1

    # When/Then the run times out, the query is cancelled and the run reported as a timeout
    try:
        with pytest.raises(HuntTimeoutError):
            connector.process_message(hunt_event)
    finally:
        release.set()
    connector.client.cancel.assert_called_once()
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "timeout")
    assert "1 seconds" in kwargs["error"]


def test_start_registers_the_sentinelone_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = SentinelOneHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered and the hunt queue consumed
    helper = helper_cls.return_value
    helper.register_hunt_platform.assert_called_once_with(
        platform="sentinelone",
        languages=["powerquery"],
        security_platform_name="SentinelOne Singularity",
        security_platform_type="EDR",
        supports_preview=True,
        max_concurrent_runs=3,
        supports_indicators=True,
        required_permissions=[
            {"name": name, "purpose": purpose}
            for name, purpose in SentinelOneHuntConnector.required_permissions
        ],
        documentation_url=SentinelOneHuntConnector.documentation_url,
    )
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )
