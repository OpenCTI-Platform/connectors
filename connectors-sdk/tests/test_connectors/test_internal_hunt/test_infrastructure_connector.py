# pragma: no cover
# type: ignore
"""Tests of the base class of the hunt connectors of internet scanning services."""

import json
from collections import Counter
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.internal_hunt import (
    Host,
    HostSearchResult,
    HuntEvent,
    HuntExecutionError,
    HuntLimits,
    HuntRequest,
    HuntResult,
    HuntTimeoutError,
    HuntTimeWindow,
    HuntTranslationError,
    InfrastructureHuntConnector,
    NativeQuery,
    infrastructure_stix_id,
    new_host,
    parse_fingerprint_rule,
    quote_value,
    render_queries,
)

from .conftest import make_hunt_config

CERT_SHA256 = "87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c"
DOCUMENT = """
fingerprints:
  - {kind: jarm, value: abc}
  - {kind: http_title, value: 'Log "in"'}
  - {kind: ja4x, value: def}
queries:
  censys: 'raw query'
  shodan: 'other platform'
"""
WINDOW = HuntTimeWindow(
    start=datetime(2026, 10, 3, tzinfo=timezone.utc),
    end=datetime(2026, 10, 4, tzinfo=timezone.utc),
)


class ScanConnector(InfrastructureHuntConnector):
    """Infrastructure hunt connector answering scripted search results."""

    service_name = "Example Scan"
    fingerprint_matches = {
        "jarm": lambda fp: f"jarm = {quote_value(fp.value)}",
        "http_title": lambda fp: f"title = {quote_value(fp.value)}",
    }

    def __init__(self, settings, results=()) -> None:
        super().__init__(settings)
        self.results = list(results)
        self.searches = []

    def search(self, query, time_window, limit, deadline):
        self.searches.append((query, limit))
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def _host(ip, domains=(), cert=None, last_seen="2026-10-03T08:00:00Z"):
    host = new_host(ip)
    for domain in domains:
        host.add_domain(domain)
    if cert:
        host.add_certificate(cert, "CN=Evil")
    host.add_fingerprint("jarm", "abc")
    host.seen(last_seen)
    return host


@pytest.fixture
def scan_settings(hunt_settings):
    hunt_settings.connector = make_hunt_config(
        scope=["censys"], security_platform_name=None
    )
    return hunt_settings


@pytest.fixture
def scan_factory(scan_settings, hunt_helper):
    def _make(results=()):
        connector = ScanConnector(scan_settings, results)
        connector._helper = hunt_helper
        connector._logger = MagicMock()
        return connector

    return _make


@pytest.fixture
def scan_event(hunt_event):
    def _make(hunt=None, **overrides):
        values = {
            "hunt_type": "infrastructure",
            "sigma_rule": None,
            "native_query": {
                "platform": "censys",
                "language": "fingerprint",
                "query": DOCUMENT,
            },
            "expected_observables": [],
            **(hunt or {}),
        }
        return hunt_event(values, security_platform=None, **overrides)

    return _make


def test_a_connector_runs_on_an_internet_scanning_platform(scan_settings):
    # Given a connector naming no service, then a telemetry platform
    class _Unnamed(ScanConnector):
        service_name = ""

    # When/Then both are rejected
    with pytest.raises(ValueError, match="must name its service"):
        _Unnamed(scan_settings)
    scan_settings.connector = make_hunt_config()
    with pytest.raises(ValueError, match="runs on one of censys"):
        ScanConnector(scan_settings)


def test_sigma_rules_are_not_translated(scan_factory):
    # Given/When a Sigma rule is translated
    # Then the hunt is asked for a fingerprint document
    with pytest.raises(HuntTranslationError, match="not translated for Example Scan"):
        scan_factory().translate("title: x", None)


def test_the_fingerprints_the_service_indexes_join_into_one_query(scan_factory):
    # Given a document with two searchable fingerprints, one other, and raw queries
    rule = parse_fingerprint_rule(DOCUMENT)

    # When its queries are built
    queries = scan_factory().fingerprint_queries(rule)

    # Then the searchable fingerprints share one query, and the raw query of the platform runs apart
    assert queries == ['(jarm = "abc") OR (title = "Log \\"in\\"")', "raw query"]
    single = parse_fingerprint_rule("fingerprints: [{kind: jarm, value: abc}]")
    assert scan_factory().fingerprint_queries(single) == ['jarm = "abc"']


def test_a_service_without_boolean_or_runs_one_query_per_fingerprint(
    scan_factory,
):
    # Given a service that cannot join matches
    connector = scan_factory()
    connector.fingerprint_join = None

    # When the queries of a document are built
    queries = connector.fingerprint_queries(parse_fingerprint_rule(DOCUMENT))

    # Then every searchable fingerprint runs apart, then the raw query
    assert queries == ['jarm = "abc"', 'title = "Log \\"in\\""', "raw query"]


def test_the_plan_is_the_query_reported(scan_factory, scan_event):
    # Given a hunt run with a fingerprint document
    request = HuntRequest.model_validate(scan_event())

    # When its query is resolved
    native = scan_factory().resolve_query(request)

    # Then the plan lists the queries, with the fields of the fingerprints searched
    assert native.language == "fingerprint"
    assert json.loads(native.query) == [
        '(jarm = "abc") OR (title = "Log \\"in\\"")',
        "raw query",
    ]
    assert native.fields == ("jarm", "http.title")


@pytest.mark.parametrize(
    ("native_query", "message"),
    [
        pytest.param(None, "no Sigma rule and no native query", id="no_query"),
        pytest.param(
            {"platform": "censys", "language": "spl", "query": "x"},
            "'spl' language is not supported",
            id="other_language",
        ),
        pytest.param(
            {"platform": "censys", "language": "fingerprint", "query": "- x"},
            "YAML mapping",
            id="invalid_document",
        ),
        pytest.param(
            {
                "platform": "censys",
                "language": "fingerprint",
                "query": "fingerprints: [{kind: ja4x, value: x}]",
            },
            r"Example Scan searches none of the fingerprints of the hunt \(ja4x\)",
            id="nothing_searchable",
        ),
    ],
)
def test_hunts_without_runnable_fingerprints_fail(
    scan_factory, hunt_helper, scan_event, native_query, message
):
    # Given a hunt without a runnable fingerprint document
    event = scan_event({"native_query": native_query})

    # When/Then the run fails with the reason
    with pytest.raises(HuntTranslationError, match=message):
        scan_factory().process_message(event)
    assert hunt_helper.report_hunt_run.call_args.args == ("run-1", "failed")


def test_a_run_maps_the_hosts_found_to_the_infrastructure(
    scan_factory, hunt_helper, scan_event
):
    # Given a service finding a public host with a domain and a certificate, then a private one
    connector = scan_factory(
        [
            HostSearchResult(
                [_host("8.8.8.8", ["c2.example.com"], CERT_SHA256)], requests=2
            ),
            HostSearchResult([_host("10.0.0.1")]),
        ]
    )

    # When the hunt run is processed
    connector.process_message(scan_event())

    # Then the plan is the reported query, every request counts, and the evidence leaves the certificates out
    args, kwargs = hunt_helper.report_hunt_run.call_args
    assert args == ("run-1", "completed")
    assert kwargs["hits_count"] == 2
    assert kwargs["query_language"] == "fingerprint"
    assert len(json.loads(kwargs["translated_query"])) == 2
    assert kwargs["queries_count"] == 3
    assert "certificates" not in {item["field"] for item in kwargs["evidence_sample"]}
    assert sorted(hit["host"] for hit in kwargs["hits_sample"]) == [
        "10.0.0.1",
        "8.8.8.8",
    ]

    # And the infrastructure grows with the public observables only
    sent = hunt_helper.stix2_create_bundle.call_args.args[0]
    assert Counter(obj["type"] for obj in sent) == {
        "infrastructure": 1,
        "ipv4-addr": 1,
        "domain-name": 1,
        "x509-certificate": 1,
        "indicator": 3,
        "relationship": 1 + 3 * 3,
        "observed-data": 3,
    }
    (infrastructure,) = [obj for obj in sent if obj["type"] == "infrastructure"]
    assert infrastructure["id"] == infrastructure_stix_id("hunt-1")
    assert "found on Example Scan by hunt run run-1" in infrastructure["description"]


def test_a_preview_plans_without_searching(scan_factory, hunt_helper, scan_event):
    # Given a preview run
    connector = scan_factory()

    # When it is processed
    connector.process_message(scan_event(mode="preview"))

    # Then the service is not searched and the plan is reported
    assert connector.searches == []
    kwargs = hunt_helper.report_hunt_run.call_args.kwargs
    assert len(json.loads(kwargs["translated_query"])) == 2


def test_the_observable_types_follow_the_hunt_and_the_settings(
    scan_factory, scan_event
):
    # Given a hunt expecting IP addresses and certificates, certificates disabled
    connector = scan_factory()
    connector.create_certificates = False
    request = HuntRequest.model_validate(
        scan_event({"expected_observables": ["IPv4-Addr", "X509-Certificate"]})
    )
    result = HuntResult(
        events=[_host_event(_host("8.8.8.8", ["c2.example.com"], CERT_SHA256))]
    )

    # When the hosts are mapped
    objects = connector.to_stix(request, result)

    # Then only the IP address is created
    types = Counter(
        (obj if isinstance(obj, dict) else obj.to_stix2_object())["type"]
        for obj in objects
    )
    assert types["ipv4-addr"] == 1
    assert "domain-name" not in types and "x509-certificate" not in types


def test_a_run_without_native_query_still_maps_its_hosts(scan_factory, scan_event):
    # Given a run request without native query (its plan ran from an earlier resolution)
    request = HuntRequest.model_validate(scan_event({"native_query": None}))
    result = HuntResult(events=[_host_event(_host("8.8.8.8"))])

    # When the hosts are mapped
    objects = scan_factory().to_stix(request, result)

    # Then the infrastructure is described without fingerprints
    assert "fingerprints of the hunt 'Encoded PowerShell' ()" in (
        objects[0].to_stix2_object()["description"]
    )


def _host_event(host: Host):
    return HuntEvent(timestamp=host.last_seen, fields=host.fields())


def _plan(*queries):
    return NativeQuery(language="fingerprint", query=render_queries(queries))


def test_the_queries_share_the_result_budget(scan_factory):
    # Given three queries, the first one reading less than its share
    connector = scan_factory(
        [
            HostSearchResult([Host(key="a")], records=1),
            HostSearchResult([Host(key="b")], total=5, records=5),
            HostSearchResult([Host(key="c")], records=4),
        ]
    )

    # When the plan runs with a budget of ten records
    result = connector.execute(
        _plan("q1", "q2", "q3"), WINDOW, HuntLimits(max_results=10)
    )

    # Then every query reads an equal share of what is left of the budget
    assert [limit for _, limit in connector.searches] == [4, 5, 4]
    assert len(result.events) == 3 and result.truncated is False
    assert result.queries_count == 3


def test_queries_are_skipped_once_the_budget_is_spent(scan_factory):
    # Given more queries than records in the budget
    connector = scan_factory(
        [HostSearchResult([Host(key="a")]), HostSearchResult([Host(key="b")])]
    )

    # When the plan runs with a budget of two records
    result = connector.execute(
        _plan("q1", "q2", "q3"), WINDOW, HuntLimits(max_results=2)
    )

    # Then the last query is skipped and the run reported as truncated
    assert len(connector.searches) == 2
    assert result.truncated is True
    connector.logger.info.assert_called_once_with(
        "[HUNT] Result budget of the run spent, infrastructure queries skipped",
        {"max_results": 2, "skipped_queries": 1},
    )


def test_the_merged_hosts_are_capped(scan_factory):
    # Given a second query finding the host of the first one and two more
    connector = scan_factory(
        [
            HostSearchResult([Host(key="a", asn=1)]),
            HostSearchResult(
                [Host(key="a", as_name="AS"), Host(key="b"), Host(key="c")]
            ),
        ]
    )

    # When the plan runs with a budget of two hosts
    result = connector.execute(_plan("q1", "q2"), WINDOW, HuntLimits(max_results=2))

    # Then the known host is merged, the new ones fill the cap and the rest is cut
    assert [event.fields.get("as_name") for event in result.events] == ["AS", None]
    assert result.truncated is True


def test_a_failing_query_leaves_a_partial_result(scan_factory):
    # Given a failing query, then one reporting more matches than it read
    connector = scan_factory(
        [
            HuntExecutionError("quota"),
            HostSearchResult([Host(key="a")], total=40),
        ]
    )

    # When the plan runs
    result = connector.execute(_plan("q1", "q2"), WINDOW, HuntLimits())

    # Then the failure is logged, the total of the service kept, and the result partial
    connector.logger.warning.assert_called_once()
    assert result.total_hits == 40
    assert result.truncated is True
    assert result.queries_count == 2


def test_a_run_fails_when_every_query_fails(scan_factory):
    # Given every query failing
    connector = scan_factory([HuntExecutionError("denied"), HuntExecutionError("x")])

    # When/Then the run fails with the first error
    with pytest.raises(HuntExecutionError, match="denied"):
        connector.execute(_plan("q1", "q2"), WINDOW, HuntLimits())


def test_timeouts_end_the_run(scan_factory):
    # Given a query timing out
    connector = scan_factory([HuntTimeoutError("too slow")])

    # When/Then the timeout ends the run
    with pytest.raises(HuntTimeoutError):
        connector.execute(_plan("q1", "q2"), WINDOW, HuntLimits())
