# pragma: no cover
# type: ignore
"""Tests of indicator hunts in the internal hunt connector base."""

from datetime import datetime, timezone

import pytest
from connectors_sdk.connectors.internal_hunt import (
    HuntEvent,
    HuntIoc,
    HuntResult,
    HuntTranslationError,
    HuntUnsupportedPyctiError,
    IocBatch,
    NativeQuery,
    aggregated_observations,
    batch_iocs,
    match_events,
    value_pattern,
)

from .conftest import DummyHuntConnector

INDICATOR_SOURCE = {
    "standard_id": "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
    "entity_type": "Indicator",
    "name": "C2 address",
}
IOCS = [
    {
        "key": "k-ip",
        "observable_type": "IPv4-Addr",
        "value": "198.51.100.7",
        "sources": [INDICATOR_SOURCE],
    },
    {
        "key": "k-domain",
        "observable_type": "Domain-Name",
        "value": "evil.example.com",
        "sources": [],
    },
    {
        "key": "k-other-ip",
        "observable_type": "IPv4-Addr",
        "value": "198.51.100.8",
        "sources": [INDICATOR_SOURCE],
    },
    {
        "key": "k-mac",
        "observable_type": "Mac-Addr",
        "value": "00:1a:2b:3c:4d:5e",
        "sources": [],
    },
]


def ioc(key, observable_type, value, hash_algorithm=None):
    return HuntIoc(
        key=key,
        observable_type=observable_type,
        value=value,
        hash_algorithm=hash_algorithm,
    )


def event(timestamp, **fields):
    return HuntEvent(timestamp=datetime.fromisoformat(timestamp), fields=fields)


class DummyIndicatorConnector(DummyHuntConnector):
    """Looks up IP addresses and domains, not MAC addresses."""

    def ioc_query(self, batch):
        if batch.observable_type == "Mac-Addr":
            return None
        return NativeQuery(language="test", query=" OR ".join(batch.values))


@pytest.fixture
def indicator_event(hunt_event):
    def _make(**overrides):
        return hunt_event(
            {"hunt_type": "indicators", "sigma_rule": None, "iocs": IOCS}, **overrides
        )

    return _make


def test_batches_values_by_type_and_hash_algorithm():
    iocs = [
        ioc("a", "IPv4-Addr", "198.51.100.1"),
        ioc("b", "IPv4-Addr", "198.51.100.2"),
        ioc("c", "IPv4-Addr", "198.51.100.3"),
        ioc("d", "StixFile", "d41d8cd98f00b204e9800998ecf8427e", "MD5"),
        ioc(
            "e",
            "StixFile",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256",
        ),
    ]
    batches = batch_iocs(iocs, 2)
    assert [
        (batch.observable_type, batch.hash_algorithm, batch.values) for batch in batches
    ] == [
        ("IPv4-Addr", None, ["198.51.100.1", "198.51.100.2"]),
        ("IPv4-Addr", None, ["198.51.100.3"]),
        ("StixFile", "MD5", ["d41d8cd98f00b204e9800998ecf8427e"]),
        (
            "StixFile",
            "SHA-256",
            ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        ),
    ]


def test_finds_values_as_whole_tokens_only():
    address = value_pattern(ioc("a", "IPv4-Addr", "1.2.3.4"))
    assert address.search("dst=1.2.3.4:443")
    assert not address.search("dst=11.2.3.4") and not address.search("dst=1.2.3.45")
    domain = value_pattern(ioc("d", "Domain-Name", "evil.com"))
    assert domain.search("GET https://cdn.EVIL.com/a") and domain.search(
        "query=evil.com."
    )
    assert (
        not domain.search("notevil.com")
        and not domain.search("evil.community")
        and not domain.search("evil.com.au")
    )
    digest = value_pattern(ioc("h", "StixFile", "d41d8cd98f00b204e9800998ecf8427e"))
    assert digest.search("md5=D41D8CD98F00B204E9800998ECF8427E")
    assert not digest.search("d41d8cd98f00b204e9800998ecf8427e00")
    url = value_pattern(ioc("u", "Url", "https://evil.com/Payload"))
    assert url.search("referer: https://evil.com/Payload?x=1") and not url.search(
        "https://evil.com/payload"
    )


def test_matches_raw_events_with_counts_times_and_hosts():
    batch = IocBatch(
        "IPv4-Addr",
        None,
        (ioc("a", "IPv4-Addr", "198.51.100.7"), ioc("b", "IPv4-Addr", "198.51.100.8")),
    )
    events = [
        event(
            "2026-10-03T10:00:00+00:00",
            DestinationIp="198.51.100.7",
            ComputerName="WKS-01",
        ),
        event("2026-10-03T08:00:00+00:00", _raw="conn to 198.51.100.7", host="SRV-02"),
        event("2026-10-03T09:00:00+00:00", _raw="conn to 198.51.100.70", host="SRV-03"),
    ]
    observations = match_events(batch, events)
    assert set(observations) == {"a"}
    seen = observations["a"]
    assert seen.hits == 2
    assert seen.first_seen == datetime(2026, 10, 3, 8, tzinfo=timezone.utc)
    assert seen.last_seen == datetime(2026, 10, 3, 10, tzinfo=timezone.utc)
    assert seen.hosts == ["WKS-01", "SRV-02"]


def test_reads_aggregated_rows_of_the_batch_only():
    batch = IocBatch("Domain-Name", None, (ioc("a", "Domain-Name", "evil.com"),))
    rows = [
        HuntEvent(
            fields={
                "ioc": "a",
                "hits": "14",
                "first_seen": "1759478400",
                "last_seen": "1759482000",
                "hosts": ["WKS-01", "WKS-02"],
            }
        ),
        HuntEvent(fields={"ioc": "not-of-the-batch", "hits": "3"}),
    ]
    observations = aggregated_observations(batch, rows)
    assert list(observations) == ["a"]
    assert observations["a"].hits == 14 and observations["a"].hosts == [
        "WKS-01",
        "WKS-02",
    ]
    assert observations["a"].first_seen == datetime.fromtimestamp(
        1759478400, tz=timezone.utc
    )


def test_a_connector_without_lookup_refuses_indicator_hunts(
    connector_factory, indicator_event, hunt_helper
):
    connector = connector_factory()
    assert connector.supports_indicators is False
    with pytest.raises(HuntTranslationError):
        connector.process_message(indicator_event())
    assert hunt_helper.report_hunt_run.call_args.args[1] == "failed"
    assert (
        "does not look up indicator values"
        in hunt_helper.report_hunt_run.call_args.kwargs["error"]
    )


def test_registers_the_indicator_lookup_capability(hunt_settings, hunt_helper):
    connector = DummyIndicatorConnector(hunt_settings)
    connector._helper = hunt_helper
    from unittest.mock import MagicMock

    connector._logger = MagicMock()
    connector.register_platform()
    assert (
        hunt_helper.register_hunt_platform.call_args.kwargs["supports_indicators"]
        is True
    )


def test_previews_the_lookups_without_running_them(
    hunt_settings, hunt_helper, indicator_event
):
    connector = DummyIndicatorConnector(hunt_settings)
    connector._helper = hunt_helper
    from unittest.mock import MagicMock

    connector._logger = MagicMock()
    connector.process_message(indicator_event(mode="preview"))
    assert connector.executed == []
    kwargs = hunt_helper.report_hunt_run.call_args.kwargs
    assert (
        kwargs["translated_query"] == "198.51.100.7 OR 198.51.100.8\n\nevil.example.com"
    )
    assert kwargs["query_language"] == "test"


def test_reports_one_result_per_value_and_sights_the_seen_ones(
    hunt_settings, hunt_helper, indicator_event
):
    result = HuntResult(
        events=[
            event(
                "2026-10-03T10:00:00+00:00", DestinationIp="198.51.100.7", host="WKS-01"
            ),
            event("2026-10-03T11:00:00+00:00", query="evil.example.com", host="WKS-02"),
            event(
                "2026-10-03T12:00:00+00:00", query="www.evil.example.com", host="WKS-02"
            ),
        ],
        truncated=False,
    )
    connector = DummyIndicatorConnector(hunt_settings, result=result)
    connector._helper = hunt_helper
    from unittest.mock import MagicMock

    connector._logger = MagicMock()
    connector.process_message(indicator_event())
    kwargs = hunt_helper.report_hunt_run.call_args.kwargs
    assert hunt_helper.report_hunt_run.call_args.args[1] == "completed"
    by_key = {item["key"]: item for item in kwargs["ioc_results"]}
    assert (
        by_key["k-ip"]["seen"] is True
        and by_key["k-ip"]["hits_count"] == 1
        and by_key["k-ip"]["hosts"] == ["WKS-01"]
    )
    assert by_key["k-domain"]["hits_count"] == 2 and by_key["k-domain"][
        "first_seen"
    ].startswith("2026-10-03T11:00:00")
    assert (
        by_key["k-other-ip"]["seen"] is False
        and by_key["k-other-ip"]["searched"] is True
    )
    assert (
        by_key["k-mac"]["searched"] is False
        and "does not look up Mac-Addr" in by_key["k-mac"]["reason"]
    )
    assert kwargs["hits_count"] == 3
    assert kwargs["distinct_entities"] == 2
    # The most seen value first, its preview within the evidence length limit
    assert kwargs["evidence_sample"][0] == {
        "field": "ioc.Domain-Name",
        "value_hash": kwargs["evidence_sample"][0]["value_hash"],
        "value_preview": "evil.example.com"[:16],
        "count": 2,
    }
    # The indicator of the address is sighted; the pasted domain is created as an observable and sighted
    bundle_objects = hunt_helper.stix2_create_bundle.call_args.args[0]
    sightings = [item for item in bundle_objects if item["type"] == "sighting"]
    assert {sighting["sighting_of_ref"] for sighting in sightings} >= {
        INDICATOR_SOURCE["standard_id"]
    }
    domain = next(
        item
        for item in bundle_objects
        if item["type"] == "domain-name" and item["value"] == "evil.example.com"
    )
    # An observable is sighted the way OpenCTI imports it: a placeholder SDO and the observable in the extension
    observable_sighting = next(
        sighting
        for sighting in sightings
        if sighting.get("x_opencti_sighting_of_ref") == domain["id"]
    )
    assert observable_sighting["sighting_of_ref"].startswith("indicator--")
    assert (
        observable_sighting["count"] == 2
        and observable_sighting["x_opencti_hunt_run_id"] == "run-1"
    )
    assert all(
        sighting["where_sighted_refs"]
        == ["identity--5b1a4c88-5ac7-4c7f-9d8c-9a5f2e8d7c01"]
        for sighting in sightings
    )
    assert set(kwargs["result_ids"]) == {item["id"] for item in bundle_objects}


def test_ignores_aggregated_rows_without_hits():
    batch = IocBatch("Domain-Name", None, (ioc("a", "Domain-Name", "evil.com"),))
    rows = [
        HuntEvent(fields={"ioc": "a", "hits": "not a number"}),
        HuntEvent(fields={"ioc": "a", "hits": "0"}),
    ]
    assert aggregated_observations(batch, rows) == {}


def test_the_default_lookup_and_keyword_detection(connector_factory):
    from connectors_sdk.connectors.internal_hunt.internal_hunt_connector import (
        _accepts_keyword,
    )

    connector = connector_factory()
    assert (
        connector.ioc_query(
            IocBatch("IPv4-Addr", None, (ioc("a", "IPv4-Addr", "198.51.100.7"),))
        )
        is None
    )
    assert _accepts_keyword(1, "anything") is False
    assert _accepts_keyword(lambda value, other=None: None, "other") is True
    assert _accepts_keyword(lambda value: None, "other") is False


def test_sends_no_sighting_without_a_security_platform(
    hunt_settings, hunt_helper, indicator_event
):
    result = HuntResult(
        events=[event("2026-10-03T10:00:00+00:00", DestinationIp="198.51.100.7")],
        truncated=False,
    )
    connector = DummyIndicatorConnector(hunt_settings, result=result)
    connector._helper = hunt_helper
    from unittest.mock import MagicMock

    connector._logger = MagicMock()
    connector.process_message(indicator_event(security_platform=None))
    kwargs = hunt_helper.report_hunt_run.call_args.kwargs
    assert kwargs["hits_count"] == 1 and kwargs["result_ids"] == []
    connector._logger.warning.assert_called_once()
    hunt_helper.send_stix2_bundle.assert_not_called()


def test_keeps_the_completed_report_when_the_sightings_cannot_be_sent(
    hunt_settings, hunt_helper, indicator_event
):
    result = HuntResult(
        events=[event("2026-10-03T10:00:00+00:00", DestinationIp="198.51.100.7")],
        truncated=False,
    )
    hunt_helper.send_stix2_bundle.side_effect = RuntimeError("broker down")
    connector = DummyIndicatorConnector(hunt_settings, result=result)
    connector._helper = hunt_helper
    from unittest.mock import MagicMock

    connector._logger = MagicMock()
    with pytest.raises(RuntimeError) as raised:
        connector.process_message(indicator_event())
    # The run stays completed: the error is marked reported, the work ends in error
    assert hunt_helper.report_hunt_run.call_count == 1
    assert hunt_helper.report_hunt_run.call_args.args[1] == "completed"
    assert raised.value.hunt_run_reported is True


def test_fails_the_run_with_a_pycti_that_cannot_report_values(
    hunt_settings, hunt_helper, indicator_event
):
    reports = []

    def report_hunt_run(
        run_id,
        status,
        hits_count=None,
        distinct_entities=None,
        evidence_sample=None,
        translated_query=None,
        query_language=None,
        cost_ms=None,
        result_ids=None,
        error=None,
        truncated=None,
    ):
        reports.append((status, error))

    hunt_helper.report_hunt_run = report_hunt_run
    connector = DummyIndicatorConnector(
        hunt_settings, result=HuntResult(events=[], truncated=False)
    )
    connector._helper = hunt_helper
    from unittest.mock import MagicMock

    connector._logger = MagicMock()
    with pytest.raises(HuntUnsupportedPyctiError):
        connector.process_message(indicator_event())
    assert (
        reports[-1][0] == "failed"
        and "cannot report the results of indicator hunts" in reports[-1][1]
    )
