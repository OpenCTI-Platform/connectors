import hashlib
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from conftest import JOBS_URL, TOKEN_URL, done, make_settings, mock_falcon_job
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from crowdstrike_logscale_hunt import CrowdstrikeLogscaleHuntConnector
from crowdstrike_logscale_hunt.client import QueryResult
from crowdstrike_logscale_hunt.connector import strip_statement_end

WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
TEN_AM_MS = "1791021600000"


def _queries(requests_mock) -> list[str]:
    return [
        request.json()["queryString"]
        for request in requests_mock.request_history
        if request.method == "POST" and request.url.endswith("/queryjobs")
    ]


def test_translate_with_the_falcon_pipeline(connector_factory, hunt_event):
    # Given/When a Sigma rule is translated with the default Falcon pipeline
    query = connector_factory().translate(hunt_event["hunt"]["sigma_rule"], None)

    # Then the LogScale query targets the Falcon process events
    assert query.language == "logscale"
    assert query.query.startswith("event_platform=/^Win$/i #event_simpleName=")
    assert "ImageFileName" in query.query


def test_translate_with_the_fdr_pipeline(connector_factory, hunt_event):
    # Given/When the hunt selects the FDR pipeline
    query = connector_factory().translate(
        hunt_event["hunt"]["sigma_rule"], "crowdstrike_fdr"
    )

    # Then the event name is a plain field
    assert query.query.startswith("event_platform=/^Win$/i event_simpleName=")


def test_translate_rejects_unknown_pipelines(connector_factory, hunt_event):
    # Given/When/Then an unknown pipeline is rejected with the supported ones
    with pytest.raises(HuntTranslationError, match="crowdstrike_falcon"):
        connector_factory().translate(hunt_event["hunt"]["sigma_rule"], "ecs_windows")


def test_combine_queries_with_or(connector_factory):
    # Given/When/Then several queries are combined with or
    assert connector_factory().combine_queries(["a=1", "b=2"]) == "(a=1) or (b=2)"


def test_strip_statement_end():
    # Given/When/Then trailing pipes and blanks are removed
    assert strip_statement_end("#event_simpleName=DnsRequest | \n") == (
        "#event_simpleName=DnsRequest"
    )


def test_execute_caps_and_maps_events(connector_factory, requests_mock):
    # Given a job returning fewer events than the cap
    mock_falcon_job(
        requests_mock,
        [
            done(
                [
                    {
                        "@timestamp": int(TEN_AM_MS),
                        "ComputerName": "ws1",
                        "@rawstring": "x",
                    }
                ]
            )
        ],
    )

    # When the query runs
    result = connector_factory().execute(
        NativeQuery(language="logscale", query="#event_simpleName=ProcessRollup2 |"),
        WINDOW,
        HuntLimits(),
    )

    # Then it is capped with tail and the events keep their time
    assert _queries(requests_mock) == [
        "#event_simpleName=ProcessRollup2\n| tail(limit=1000)"
    ]
    assert result.hits_count == 1
    assert result.truncated is False
    assert result.events[0].timestamp == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)


def test_execute_counts_when_the_cap_is_reached(connector_factory, requests_mock):
    # Given more events than the cap
    requests_mock.post(TOKEN_URL, json={"access_token": "tok"})
    requests_mock.post(JOBS_URL, [{"json": {"id": "j1"}}, {"json": {"id": "j2"}}])
    requests_mock.get(f"{JOBS_URL}/j1", json=done([{"timestamp": TEN_AM_MS}]))
    requests_mock.get(f"{JOBS_URL}/j2", json=done([{"_count": "42"}]))
    requests_mock.delete(f"{JOBS_URL}/j1", status_code=204)
    requests_mock.delete(f"{JOBS_URL}/j2", status_code=204)

    # When the query runs with a cap of one event
    result = connector_factory().execute(
        NativeQuery(language="logscale", query="q"), WINDOW, HuntLimits(max_results=1)
    )

    # Then the total comes from the count query
    assert _queries(requests_mock) == ["q\n| tail(limit=1)", "q\n| count()"]
    assert (result.hits_count, result.truncated) == (42, True)
    assert result.events[0].timestamp == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "count_events, expected",
    [
        pytest.param([{"_count": 7}], 7, id="number"),
        pytest.param([], 1, id="no_event"),
        pytest.param([{"_count": "n/a"}], 1, id="not_a_number"),
    ],
)
def test_execute_reads_the_count(connector_factory, count_events, expected):
    # Given a client whose count query answers in various shapes
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.query.side_effect = [
        QueryResult([{"a": 1}], []),
        QueryResult(count_events, []),
    ]

    # When/Then the hit count is read when usable
    result = connector.execute(
        NativeQuery(language="logscale", query="q"), WINDOW, HuntLimits(max_results=1)
    )
    assert result.hits_count == expected
    assert result.events[0].timestamp is None


def test_execute_logs_warnings(connector_factory):
    # Given a query answering with warnings
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.query.return_value = QueryResult([], ["w"] * 7)

    # When the query runs
    connector.execute(NativeQuery(language="logscale", query="q"), WINDOW, HuntLimits())

    # Then the first warnings are logged
    connector.logger.warning.assert_called_once_with(
        "[LOGSCALE] Query warnings", {"warnings": ["w"] * 5}
    )


def test_execute_requires_start():
    # Given/When/Then a connector that is not started has no client
    connector = CrowdstrikeLogscaleHuntConnector(make_settings())
    with pytest.raises(RuntimeError):
        connector.execute(
            NativeQuery(language="logscale", query="q"), WINDOW, HuntLimits()
        )


def test_logscale_deployment_uses_the_cluster(connector_factory, requests_mock):
    # Given a LogScale cluster deployment
    connector = connector_factory(
        {
            "crowdstrike_logscale_hunt": {
                "deployment": "logscale",
                "logscale_url": "https://logscale.example.com",
                "logscale_token": "ls-token",
                "repository": "windows",
            }
        }
    )
    jobs = "https://logscale.example.com/api/v1/repositories/windows/queryjobs"
    requests_mock.post(jobs, json={"id": "j1"})
    requests_mock.get(f"{jobs}/j1", json=done([]))
    requests_mock.delete(f"{jobs}/j1", status_code=204)

    # When the query runs
    connector.execute(NativeQuery(language="logscale", query="q"), WINDOW, HuntLimits())

    # Then the cluster API is queried with the API token
    assert requests_mock.request_history[0].headers["Authorization"] == (
        "Bearer ls-token"
    )


def test_on_timeout_cancels_the_job_of_the_query(connector_factory):
    # Given a started connector
    connector = connector_factory()
    connector.client = MagicMock()
    query = NativeQuery(language="logscale", query="q")

    # When/Then the job of that query is cancelled
    connector.on_timeout(query)
    connector.client.cancel.assert_called_once_with(id(query))


def test_on_timeout_without_client():
    # Given/When/Then a connector that is not started has nothing to cancel
    CrowdstrikeLogscaleHuntConnector(make_settings()).on_timeout(
        NativeQuery(language="logscale", query="q")
    )


def test_process_message_reports_hits_and_sends_knowledge(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given events with a public IP, a private IP and a benign host
    mock_falcon_job(
        requests_mock,
        [
            done(
                [
                    {
                        "timestamp": TEN_AM_MS,
                        "ComputerName": "ws1",
                        "RemoteAddressIP4": "8.8.8.8",
                        "@rawstring": "raw",
                        "aid": "a1",
                    },
                    {
                        "timestamp": TEN_AM_MS,
                        "ComputerName": "ws2",
                        "RemoteAddressIP4": "10.0.0.1",
                        "@rawstring": "raw",
                        "aid": "a2",
                    },
                    {
                        "timestamp": TEN_AM_MS,
                        "ComputerName": "sccm01",
                        "RemoteAddressIP4": "1.1.1.1",
                        "@rawstring": "raw",
                        "aid": "a3",
                    },
                ]
            )
        ],
    )
    hunt_event["hunt"]["benign_patterns"] = ["/^sccm\\d+$/"]

    # When the hunt run is processed
    message = connector_factory().process_message(hunt_event)

    # Then the run is reported with the translated query and redacted evidence
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["query_language"] == "logscale"
    assert kwargs["translated_query"].startswith("event_platform=")
    fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert "@rawstring" not in fields and "aid" not in fields
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
    mock_falcon_job(
        requests_mock,
        [done([{"CommandLine": command_line}, {"CommandLine": command_line}])],
    )
    hunt_event["limits"]["evidence_max_value_length"] = 20

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the evidence holds the hash of the full value and a truncated preview
    evidence = helper.report_hunt_run.call_args.kwargs["evidence_sample"]
    assert evidence == [
        {
            "field": "CommandLine",
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

    # Then LogScale is never queried
    assert requests_mock.call_count == 0
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["query_language"] == "logscale"


def test_process_message_executes_native_queries(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a native LogScale query for CrowdStrike LogScale
    mock_falcon_job(requests_mock, [done([])])
    hunt_event["hunt"]["native_query"] = {
        "platform": "crowdstrike-logscale",
        "language": "logscale",
        "query": "#event_simpleName=DnsRequest | groupBy([DomainName])",
    }

    # When the run is processed
    connector_factory().process_message(hunt_event)

    # Then the query runs verbatim (capped) and reports no hit
    assert _queries(requests_mock) == [
        "#event_simpleName=DnsRequest | groupBy([DomainName])\n| tail(limit=100)"
    ]
    assert helper.report_hunt_run.call_args.kwargs["hits_count"] == 0
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_reports_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given an API client without the Next-Gen SIEM search scope
    requests_mock.post(TOKEN_URL, json={"access_token": "tok"})
    requests_mock.post(
        JOBS_URL, status_code=403, json={"errors": [{"message": "access denied"}]}
    )

    # When/Then the run fails and is reported failed with the reason
    with pytest.raises(HuntExecutionError):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "access denied" in kwargs["error"]
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_times_out(connector_factory, helper, hunt_event):
    # Given a query that never completes within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.client = MagicMock()
    connector.client.query.side_effect = lambda *args: release.wait(5)
    hunt_event["limits"]["timeout_seconds"] = 1

    # When/Then the run times out, the job is cancelled and the run reported failed
    try:
        with pytest.raises(HuntTimeoutError):
            connector.process_message(hunt_event)
    finally:
        release.set()
    connector.client.cancel.assert_called_once()
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    assert "1 seconds" in kwargs["error"]


def test_start_registers_the_logscale_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = CrowdstrikeLogscaleHuntConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the platform is registered and the hunt queue consumed
    helper = helper_cls.return_value
    helper.register_hunt_platform.assert_called_once_with(
        platform="crowdstrike-logscale",
        languages=["logscale"],
        security_platform_name="CrowdStrike Falcon",
        security_platform_type="SIEM",
        supports_preview=True,
        max_concurrent_runs=None,
    )
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )


def test_start_fails_fast_without_the_pycti_hunt_api():
    # Given a pycti without the hunt connector API
    connector = CrowdstrikeLogscaleHuntConnector(make_settings())
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
