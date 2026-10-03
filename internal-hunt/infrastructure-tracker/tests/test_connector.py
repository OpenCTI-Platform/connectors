import json
import threading
from collections import Counter
from datetime import date, datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from conftest import (
    CENSYS_URL,
    CERT_SHA256,
    INTERNETDB_URL,
    JARM,
    SCOUT_URL,
    TARGETS,
    URLSCAN_URL,
    censys_answer,
    censys_host,
    make_settings,
)
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    HuntLimits,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    NativeQuery,
)
from infrastructure_tracker import InfrastructureTrackerConnector
from infrastructure_tracker.connector import _today, describe_rule, scout_window
from infrastructure_tracker.rule import parse_rule, render_plan
from infrastructure_tracker.sources import (
    CensysClient,
    Host,
    ScoutClient,
    SilentPushClient,
    SourceResult,
    UrlscanClient,
)

SDK_CONNECTOR = "connectors_sdk.connectors.internal_hunt.internal_hunt_connector"
TRACKER = "infrastructure_tracker.connector"
AUTHOR = "identity--7b82b010-b1c0-4dae-981f-7756374a17df"
MARKING = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
WINDOW = HuntTimeWindow(
    start=datetime(2026, 10, 3, tzinfo=timezone.utc),
    end=datetime(2026, 10, 4, tzinfo=timezone.utc),
)
ALL_SOURCES = {
    "infrastructure_tracker": {
        "silentpush_api_key": "sp",
        "urlscan_api_key": "us",
        "cymru_scout_api_key": "cs",
    }
}


def plan_query(plan: dict[str, list[str]]) -> NativeQuery:
    return NativeQuery(language="internet", query=render_plan(plan))


def test_post_init_creates_the_configured_clients(connector_factory):
    connector = connector_factory(
        {"infrastructure_tracker": {**ALL_SOURCES["infrastructure_tracker"]}}
    )
    assert [type(client) for client in connector.clients.values()] == [
        CensysClient,
        SilentPushClient,
        UrlscanClient,
        ScoutClient,
    ]
    assert connector.internetdb is None


def test_post_init_creates_the_internetdb_client(connector_factory):
    connector = connector_factory(
        {"infrastructure_tracker": {"internetdb_enabled": True}}
    )
    assert connector.internetdb is not None
    disabled = connector_factory(
        {
            "infrastructure_tracker": {
                "internetdb_enabled": True,
                "internetdb_max_lookups": 0,
            }
        }
    )
    assert disabled.internetdb is None


def test_sigma_rules_are_not_translated(connector_factory):
    connector = connector_factory()
    with pytest.raises(HuntTranslationError, match="native query in the 'internet'"):
        connector.translate("title: x", None)


def test_scout_window_keeps_the_most_recent_searchable_days():
    today = date(2026, 10, 4)
    assert scout_window(WINDOW, today) == (date(2026, 10, 3), date(2026, 10, 4))
    wide = HuntTimeWindow(
        start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end=datetime(2026, 12, 31, tzinfo=timezone.utc),
    )
    assert scout_window(wide, today) == (date(2026, 9, 5), date(2026, 10, 4))
    assert scout_window(WINDOW, date(2027, 1, 30)) is None


def test_today_is_the_utc_date():
    assert _today() == datetime.now(timezone.utc).date()


def test_describe_rule():
    rule = parse_rule(
        "fingerprints:\n"
        + "".join(f"  - {{kind: jarm, value: j{index}}}\n" for index in range(7))
        + "queries:\n  urlscan: q\n  censys: q\n"
    )
    assert describe_rule(rule) == (
        "jarm j0, jarm j1, jarm j2, jarm j3, jarm j4, 2 more, queries on censys, urlscan"
    )


def test_process_message_maps_the_infrastructure(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given Censys hosts: a public one with a domain, a private one, a benign one
    requests_mock.post(
        CENSYS_URL,
        json=censys_answer(
            [
                censys_host("8.8.8.8", ["c2.update-cdn.net"]),
                censys_host("10.0.0.1", ["intranet.local"], cert=None),
                censys_host("1.1.1.1", ["one.one.one.one"], cert=None),
            ]
        ),
    )
    hunt_event["hunt"]["benign_patterns"] = ["1.1.1.1"]

    # When the hunt run is processed
    message = connector_factory().process_message(hunt_event)

    # Then the plan is the reported query and the evidence holds fingerprints only
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["distinct_entities"] == 4
    assert kwargs["query_language"] == "internet"
    plan = json.loads(kwargs["translated_query"])
    assert list(plan) == ["censys"]
    assert f'host.services.jarm.fingerprint = "{JARM}"' in plan["censys"][0]
    evidence_fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert "certificates" not in evidence_fields
    assert "jarm" in evidence_fields
    assert "2 hit(s)" in message

    # And the infrastructure, its public observables and detection indicators are sent
    sent = helper.stix2_create_bundle.call_args.args[0]
    by_type = Counter(obj["type"] for obj in sent)
    assert by_type == {
        "infrastructure": 1,
        "ipv4-addr": 1,
        "domain-name": 1,
        "x509-certificate": 1,
        "indicator": 3,
        "relationship": 2 + 3 * 2 + 3 * 2,
    }
    (infrastructure,) = [obj for obj in sent if obj["type"] == "infrastructure"]
    assert infrastructure["name"] == "Cobalt Strike team servers"
    assert "run-1" in infrastructure["description"]
    assert infrastructure["first_seen"] == "2026-10-03T08:00:00Z"
    assert [o["value"] for o in sent if o["type"] == "ipv4-addr"] == ["8.8.8.8"]
    assert [o["value"] for o in sent if o["type"] == "domain-name"] == [
        "c2.update-cdn.net"
    ]
    (certificate,) = [o for o in sent if o["type"] == "x509-certificate"]
    assert certificate["hashes"] == {"SHA-256": CERT_SHA256}
    indicators = [o for o in sent if o["type"] == "indicator"]
    assert {o["pattern"] for o in indicators} == {
        "[ipv4-addr:value = '8.8.8.8']",
        "[domain-name:value = 'c2.update-cdn.net']",
        f"[x509-certificate:hashes.'SHA-256' = '{CERT_SHA256}']",
    }
    assert all(o["x_opencti_detection"] is True for o in indicators)
    assert {o["x_opencti_main_observable_type"] for o in indicators} == {
        "IPv4-Addr",
        "Domain-Name",
        "X509-Certificate",
    }
    relationships = Counter(
        obj["relationship_type"] for obj in sent if obj["type"] == "relationship"
    )
    assert relationships == {
        "related-to": 2,
        "consists-of": 3,
        "based-on": 3,
        "indicates": 6,
    }
    targets = {target["standard_id"] for target in TARGETS}
    for obj in sent:
        if obj["type"] == "relationship" and obj["relationship_type"] in (
            "related-to",
            "indicates",
        ):
            assert obj["target_ref"] in targets
    for obj in sent:
        assert obj["object_marking_refs"] == [MARKING]
        assert AUTHOR in (
            obj.get("created_by_ref"),
            obj.get("x_opencti_created_by_ref"),
        )
    helper.send_stix2_bundle.assert_called_once()


def test_process_message_restricts_the_observable_types(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a hunt expecting IP addresses and certificates, certificates disabled
    requests_mock.post(
        CENSYS_URL, json=censys_answer([censys_host("8.8.8.8", ["c2.update-cdn.net"])])
    )
    hunt_event["hunt"]["expected_observables"] = ["IPv4-Addr", "X509-Certificate"]
    hunt_event["hunt"]["targets"] = []
    connector = connector_factory(
        {"infrastructure_tracker": {"create_certificates": False}}
    )

    # When the run is processed
    connector.process_message(hunt_event)

    # Then only the IP address is created, without threat relationships
    sent = helper.stix2_create_bundle.call_args.args[0]
    assert Counter(obj["type"] for obj in sent) == {
        "infrastructure": 1,
        "ipv4-addr": 1,
        "indicator": 1,
        "relationship": 2,
    }


def test_process_message_without_hits_sends_nothing(
    connector_factory, helper, requests_mock, hunt_event
):
    requests_mock.post(CENSYS_URL, json=censys_answer([]))

    connector_factory().process_message(hunt_event)

    assert helper.report_hunt_run.call_args.kwargs["hits_count"] == 0
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_preview_plans_without_searching(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a preview run with every source configured
    hunt_event["mode"] = "preview"

    # When it is processed
    connector_factory(ALL_SOURCES).process_message(hunt_event)

    # Then no source is queried and the plan lists the sources searching the rule
    assert requests_mock.call_count == 0
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    plan = json.loads(kwargs["translated_query"])
    assert list(plan) == ["censys", "silentpush", "cymru_scout"]
    assert plan["cymru_scout"] == [JARM]


@pytest.mark.parametrize(
    ("native_query", "message"),
    [
        (None, "native query in the 'internet' language"),
        (
            {"platform": "internet", "language": "spl", "query": "index=*"},
            "internet",
        ),
        (
            {"platform": "internet", "language": "internet", "query": "- x"},
            "YAML mapping",
        ),
        (
            {
                "platform": "internet",
                "language": "internet",
                "query": "fingerprints:\n  - {kind: ja4x, value: x}\nsources: [urlscan]\n",
            },
            "is configured",
        ),
    ],
)
def test_process_message_rejects_invalid_hunts(
    connector_factory, helper, hunt_event, native_query, message
):
    # Given a hunt without a runnable fingerprint rule
    hunt_event["hunt"]["native_query"] = native_query
    hunt_event["hunt"]["sigma_rule"] = "title: x\ndetection: {}\n"

    # When/Then the run fails with the reason
    with pytest.raises(HuntTranslationError, match=message):
        connector_factory().process_message(hunt_event)
    assert helper.report_hunt_run.call_args.args == ("run-1", "failed")


def test_process_message_reports_source_failures(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given the only source rejecting the token
    requests_mock.post(CENSYS_URL, status_code=401, json={"error": "invalid token"})

    # When/Then the run fails with the source error
    with pytest.raises(HuntExecutionError, match="Censys"):
        connector_factory().process_message(hunt_event)
    args, kwargs = helper.report_hunt_run.call_args
    assert args == ("run-1", "failed")
    helper.send_stix2_bundle.assert_not_called()


@patch(f"{TRACKER}._today", return_value=date(2026, 10, 4))
def test_execute_merges_the_sources_and_skips_failures(
    _, connector_factory, requests_mock
):
    # Given Censys failing and urlscan and Scout finding the same IP address
    requests_mock.post(CENSYS_URL, status_code=403, json={"error": "quota"})
    requests_mock.get(
        URLSCAN_URL,
        json={
            "results": [{"page": {"ip": "8.8.8.8", "domain": "evil.example"}}],
            "total": 1,
        },
    )
    requests_mock.get(
        SCOUT_URL,
        json={
            "ips": [{"ip": "8.8.8.8", "summary": {"pdns": [{"domain": "c2.example"}]}}]
        },
    )
    connector = connector_factory(ALL_SOURCES)
    plan = {"censys": ["q"], "urlscan": ["q"], "cymru_scout": [JARM]}

    # When the plan runs
    result = connector.execute(plan_query(plan), WINDOW, HuntLimits())

    # Then the failure is logged and the hosts merged
    connector.logger.warning.assert_called_once()
    (event,) = result.events
    assert event.fields["source"] == ["urlscan", "cymru_scout"]
    assert event.fields["domain"] == ["evil.example", "c2.example"]
    assert result.total_hits == 1 and result.truncated is False


@patch(f"{TRACKER}._today", return_value=date(2027, 6, 1))
def test_execute_skips_scout_for_old_windows(_, connector_factory, requests_mock):
    connector = connector_factory(ALL_SOURCES)

    result = connector.execute(
        plan_query({"cymru_scout": [JARM]}), WINDOW, HuntLimits()
    )

    assert requests_mock.call_count == 0
    assert result.events == []
    connector.logger.info.assert_called_once()


def test_execute_flags_truncation(connector_factory, requests_mock):
    # Given more matches than the run reads
    requests_mock.post(
        CENSYS_URL,
        json=censys_answer([censys_host("8.8.8.8"), censys_host("9.9.9.9")], total=500),
    )
    connector = connector_factory()

    # When the plan runs twice on the same source with a one host limit
    result = connector.execute(
        plan_query({"censys": ["q1", "q2"]}), WINDOW, HuntLimits(max_results=2)
    )

    # Then the extra hosts are dropped and the source total reported
    assert result.truncated is True
    assert result.total_hits == 500
    assert len(result.events) == 2


def test_execute_caps_the_merged_hosts(connector_factory):
    connector = connector_factory()
    connector.clients["censys"] = MagicMock()
    connector.clients["censys"].search.side_effect = [
        SourceResult([Host(key="a", sources=["censys"])]),
        SourceResult([Host(key="a", sources=["censys"]), Host(key="b")]),
    ]

    result = connector.execute(
        plan_query({"censys": ["q1", "q2"]}), WINDOW, HuntLimits(max_results=1)
    )

    assert [event.fields.get("source") for event in result.events] == [["censys"]]
    assert result.truncated is True


def test_execute_fails_on_unconfigured_sources(connector_factory):
    with pytest.raises(HuntExecutionError, match="'urlscan' source is not configured"):
        connector_factory().execute(
            plan_query({"urlscan": ["q"]}), WINDOW, HuntLimits()
        )


def test_execute_propagates_timeouts(connector_factory):
    connector = connector_factory()
    connector.clients["censys"] = MagicMock()
    connector.clients["censys"].search.side_effect = HuntTimeoutError("too slow")

    with pytest.raises(HuntTimeoutError):
        connector.execute(plan_query({"censys": ["q"]}), WINDOW, HuntLimits())


def test_execute_enriches_public_ips_with_internetdb(connector_factory, requests_mock):
    # Given three hosts, one private, and InternetDB failing for one IP address
    requests_mock.post(
        CENSYS_URL,
        json=censys_answer(
            [censys_host("8.8.8.8"), censys_host("10.0.0.1"), censys_host("9.9.9.9")]
        ),
    )
    requests_mock.get(f"{INTERNETDB_URL}/8.8.8.8", json={"hostnames": ["dns.google"]})
    requests_mock.get(f"{INTERNETDB_URL}/9.9.9.9", status_code=403, text="denied")
    connector = connector_factory(
        {"infrastructure_tracker": {"internetdb_enabled": True}}
    )

    # When the plan runs
    result = connector.execute(plan_query({"censys": ["q"]}), WINDOW, HuntLimits())

    # Then the known public IP address is enriched and the failure logged
    first, private, failed = result.events
    assert first.fields["source"] == ["censys", "internetdb"]
    assert first.fields["domain"] == ["dns.google"]
    assert private.fields["source"] == ["censys"]
    assert failed.fields["source"] == ["censys"]
    connector.logger.warning.assert_called_once()


def test_enrichment_respects_the_lookup_limit_and_the_deadline(
    connector_factory, monkeypatch
):
    connector = connector_factory(
        {
            "infrastructure_tracker": {
                "internetdb_enabled": True,
                "internetdb_max_lookups": 1,
            }
        }
    )
    connector.internetdb = MagicMock()
    connector.internetdb.lookup.return_value = False
    hosts = [Host(key="8.8.8.8", ip="8.8.8.8"), Host(key="9.9.9.9", ip="9.9.9.9")]
    deadline = MagicMock()
    deadline.remaining.return_value = 60

    connector._enrich(hosts, deadline)
    assert connector.internetdb.lookup.call_count == 1
    assert hosts[0].sources == []

    deadline.remaining.return_value = 1
    connector._enrich(hosts, deadline)
    assert connector.internetdb.lookup.call_count == 1
    connector.logger.info.assert_called_once()


def test_enrichment_stops_on_timeouts(connector_factory):
    connector = connector_factory(
        {"infrastructure_tracker": {"internetdb_enabled": True}}
    )
    connector.internetdb = MagicMock()
    connector.internetdb.lookup.side_effect = HuntTimeoutError("too slow")
    hosts = [Host(key="8.8.8.8", ip="8.8.8.8"), Host(key="9.9.9.9", ip="9.9.9.9")]
    deadline = MagicMock()
    deadline.remaining.return_value = 60

    connector._enrich(hosts, deadline)

    assert connector.internetdb.lookup.call_count == 1
    connector.logger.warning.assert_called_once()


def test_process_message_times_out(connector_factory, helper, hunt_event):
    # Given a source that never answers within the run timeout
    release = threading.Event()
    connector = connector_factory()
    connector.clients["censys"] = MagicMock()
    connector.clients["censys"].search.side_effect = lambda *args: release.wait(5)
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


def test_start_registers_the_internet_platform_and_listens():
    # Given a pycti providing the hunt API
    connector = InfrastructureTrackerConnector(make_settings())
    with (
        patch(f"{SDK_CONNECTOR}.ensure_pycti_hunt_support"),
        patch(f"{SDK_CONNECTOR}.OpenCTIConnectorHelper") as helper_cls,
    ):
        # When the connector starts
        connector.start()

    # Then the internet platform is registered without a Security Platform
    helper = helper_cls.return_value
    call = helper.register_hunt_platform.call_args
    assert call.kwargs["platform"] == "internet"
    assert call.kwargs["languages"] == ["internet"]
    assert call.kwargs["security_platform_name"] is None
    assert call.kwargs["supports_preview"] is True
    helper.listen_hunt.assert_called_once_with(
        message_callback=connector.process_message
    )
    assert list(connector.clients) == ["censys"]
