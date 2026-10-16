# pragma: no cover
# type: ignore
"""Tests of the hosts found by infrastructure hunts and of their STIX mapping."""

from collections import Counter
from datetime import datetime, timezone

import pytest
from connectors_sdk.connectors.internal_hunt import (
    Host,
    HostSearchResult,
    HuntEvent,
    HuntExecutionError,
    HuntInfrastructure,
    HuntRequest,
    HuntTimeWindow,
    as_list,
    as_mapping,
    build_infrastructure_objects,
    collect_infrastructure_observables,
    infrastructure_name,
    infrastructure_stix_id,
    json_object,
    new_host,
    parse_asn,
    text_value,
    within_window,
)

CERT_SHA256 = "87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c"
CERT_SUBJECT = "CN=Major Cobalt Strike, O=cobaltstrike"
JARM = "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"
WINDOW = HuntTimeWindow(
    start=datetime(2026, 10, 3, tzinfo=timezone.utc),
    end=datetime(2026, 10, 4, tzinfo=timezone.utc),
)
FIRST = datetime(2026, 10, 3, 1, tzinfo=timezone.utc)
LAST = datetime(2026, 10, 3, 5, tzinfo=timezone.utc)


def test_values_read_from_answers_are_typed_safely():
    # Given/When values of unexpected types are read
    # Then text, mappings, lists and ASNs fall back to empty values
    assert text_value("  a ") == "a"
    assert text_value(443) == "443"
    assert text_value(True) == ""
    assert text_value({"a": 1}) == ""
    assert as_mapping({"a": 1}) == {"a": 1}
    assert as_mapping([1]) == {}
    assert as_list([1]) == [1]
    assert as_list({"a": 1}) == []
    assert parse_asn("AS13335") == 13335
    assert parse_asn(20473) == 20473
    assert parse_asn("ASX") is None


def test_answers_must_be_json_objects():
    # Given/When an answer is a JSON object, then a list
    # Then the object is returned and the list rejected
    assert json_object({"a": 1}, "The search") == {"a": 1}
    with pytest.raises(HuntExecutionError, match="The search returned an unexpected"):
        json_object([], "The search")


def test_a_host_collects_unique_values():
    # Given a host fed with duplicates and invalid values
    host = Host(key="8.8.8.8", ip="8.8.8.8")
    host.add_domain("Evil.Example.")
    host.add_domain("evil.example")
    host.add_domain(None)
    host.add_port(443)
    host.add_port("8443")
    host.add_port("https")
    host.add_port(True)
    host.add_certificate(CERT_SHA256.upper(), CERT_SUBJECT)
    host.add_certificate(CERT_SHA256)
    host.add_certificate("not-a-hash")
    host.add_certificate("z" * 64)
    host.add_fingerprint("jarm", JARM)
    host.add_fingerprint("jarm", "")
    host.add_fingerprint("jarm", {"nested": 1})
    host.add_url("https://evil.example/")
    host.add_url(None)
    host.add_tag({"name": "cobalt-strike"})
    host.add_tag("c2")
    host.add_tag({"id": 1})
    host.seen("2026-10-03T08:00:00Z")
    host.seen("2026-10-02T08:00:00Z")
    host.seen("garbage")

    # When/Then its event fields hold each valid value once
    assert host.fields() == {
        "ip": "8.8.8.8",
        "domain": ["evil.example"],
        "port": [443, 8443],
        "certificate.sha256": [CERT_SHA256],
        "certificate.subject": [CERT_SUBJECT],
        "certificates": [
            {"sha256": CERT_SHA256, "subject": CERT_SUBJECT, "issuer": None}
        ],
        "jarm": [JARM],
        "url": ["https://evil.example/"],
        "tag": ["cobalt-strike", "c2"],
    }
    assert host.last_seen == datetime(2026, 10, 3, 8, tzinfo=timezone.utc)


def test_a_fingerprint_named_like_a_certificate_field_joins_its_values():
    # Given a host whose certificate names an issuer, and an issuer fingerprinted apart
    host = Host(key="8.8.8.8", ip="8.8.8.8")
    host.add_certificate(CERT_SHA256, CERT_SUBJECT, "CN=Evil CA")
    host.add_fingerprint("certificate.issuer", "R3")
    host.add_fingerprint("certificate.issuer", "CN=Evil CA")

    # When/Then the field holds both issuers once
    assert host.fields()["certificate.issuer"] == ["CN=Evil CA", "R3"]


def test_hosts_merge():
    # Given two matches of the same host
    first = Host(key="8.8.8.8", ip="8.8.8.8", asn=15169)
    second = Host(key="8.8.8.8", ip="8.8.8.8", asn=1, as_name="GOOGLE")
    second.add_domain("dns.google")
    second.add_port(53)
    second.add_certificate(CERT_SHA256, issuer="CN=CA")
    second.add_fingerprint("http.title", "Google")
    second.add_url("https://8.8.8.8/")
    second.add_tag("dns")
    second.seen("2026-10-03T08:00:00Z")

    # When they are merged (and an empty match after them)
    first.merge(second)
    first.merge(Host(key="8.8.8.8"))

    # Then the first keeps its values and gains the others
    assert first.asn == 15169 and first.as_name == "GOOGLE"
    assert first.domains == ["dns.google"] and first.ports == [53]
    assert first.certificates[0].issuer == "CN=CA"
    assert first.fingerprints == {"http.title": ["Google"]}
    assert first.urls == ["https://8.8.8.8/"] and first.tags == ["dns"]
    assert first.last_seen == datetime(2026, 10, 3, 8, tzinfo=timezone.utc)


def test_a_host_is_keyed_by_its_address_else_its_name():
    # Given/When hosts are created from addresses and names
    # Then the address keys the host, else the name (kept as a domain)
    assert new_host() is None
    assert new_host(None, "Host.Example.").key == "host.example"
    host = new_host("1.2.3.4", "host.example")
    assert host.key == "1.2.3.4" and host.domains == ["host.example"]


def test_a_search_result_counts_the_records_read():
    # Given/When results with and without a record count
    hosts = [Host(key="a"), Host(key="b")]

    # Then the records read default to the hosts, and a larger total truncates
    assert HostSearchResult(hosts).read == 2
    assert HostSearchResult(hosts, records=5).read == 5
    assert HostSearchResult(hosts, total=3).truncated is True
    assert HostSearchResult(hosts, total=2).truncated is False
    assert HostSearchResult(hosts, more=True).truncated is True


def test_only_the_hosts_scanned_during_the_run_window_are_kept():
    # Given hosts scanned inside, before and after the window, and one without time
    inside = Host(
        key="8.8.8.8", last_seen=datetime(2026, 10, 3, 8, tzinfo=timezone.utc)
    )
    before = Host(key="8.8.4.4", last_seen=datetime(2026, 9, 1, tzinfo=timezone.utc))
    after = Host(key="1.1.1.1", last_seen=datetime(2026, 10, 5, tzinfo=timezone.utc))
    unknown = Host(key="9.9.9.9")

    # When the window filters them
    result = within_window(
        HostSearchResult([inside, before, after, unknown], 12, requests=3), WINDOW
    )

    # Then the total, which also counted the hosts dropped, is not kept: the truncation is
    assert [host.key for host in result.hosts] == ["8.8.8.8", "9.9.9.9"]
    assert result.total is None
    assert result.read == 4
    assert result.truncated is True
    assert result.requests == 3
    complete = HostSearchResult([inside, unknown], 2)
    assert within_window(complete, WINDOW) is complete
    assert within_window(HostSearchResult([before], 1), WINDOW).truncated is False


def test_the_total_of_a_truncated_page_is_never_kept():
    # Given every host read inside the window, but 48 matches left unread
    inside = Host(
        key="8.8.8.8", last_seen=datetime(2026, 10, 3, 8, tzinfo=timezone.utc)
    )

    # When the window filters them
    result = within_window(HostSearchResult([inside, Host(key="9.9.9.9")], 50), WINDOW)

    # Then only the hosts read count, and the result stays truncated
    assert result.total is None
    assert [host.key for host in result.hosts] == ["8.8.8.8", "9.9.9.9"]
    assert result.read == 2
    assert result.truncated is True


def _event(ip, domains=(), certificates=()):
    host = new_host(ip)
    for domain in domains:
        host.add_domain(domain)
    for sha256, subject in certificates:
        host.add_certificate(sha256, subject)
    return HuntEvent(fields=host.fields())


def test_observables_are_public_and_counted_by_host():
    # Given three hosts sharing a domain and a certificate, one with a private address
    events = [
        _event("8.8.8.8", ["c2.example.com"], [(CERT_SHA256, CERT_SUBJECT)]),
        _event("9.9.9.9", ["c2.example.com"], [(CERT_SHA256, "CN=Other")]),
        _event("10.0.0.1", ["intranet.local"], [(CERT_SHA256, CERT_SUBJECT)]),
    ]

    # When the observables are collected
    observables = collect_infrastructure_observables(
        events, ["IPv4-Addr", "Domain-Name", "X509-Certificate"], 10
    )

    # Then the most frequent come first, and a certificate keeps its most frequent subject
    assert [(o.observable_type, o.value, o.count) for o in observables] == [
        ("X509-Certificate", CERT_SHA256, 3),
        ("Domain-Name", "c2.example.com", 2),
        ("IPv4-Addr", "8.8.8.8", 1),
        ("IPv4-Addr", "9.9.9.9", 1),
    ]
    assert observables[0].subject == CERT_SUBJECT
    assert collect_infrastructure_observables(events, ["IPv4-Addr"], 1)[0].value == (
        "8.8.8.8"
    )
    assert collect_infrastructure_observables(events, ["IPv4-Addr"], -1) == []


def test_the_infrastructure_name_carries_the_full_hunt_id():
    # Given/When two hunts share a name and an id prefix
    first = infrastructure_name("C2 servers", "3f2a9c1d-0000-4000-8000-000000000001")
    second = infrastructure_name("C2 servers", "3f2a9c1d-0000-4000-8000-000000000002")

    # Then they still name two infrastructures
    assert first == "C2 servers (hunt 3f2a9c1d-0000-4000-8000-000000000001)"
    assert first != second


def test_the_infrastructure_id_follows_the_hunt_not_its_name():
    # Given the infrastructure of a hunt, before and after a rename
    hunt_id = "3f2a9c1d-0000-4000-8000-000000000001"
    before = HuntInfrastructure(
        hunt_id=hunt_id, name=infrastructure_name("C2", hunt_id)
    )
    renamed = HuntInfrastructure(
        hunt_id=hunt_id, name=infrastructure_name("C2 servers", hunt_id)
    )

    # When/Then both share the id seeded from the hunt id
    other = infrastructure_stix_id("3f2a9c1d-0000-4000-8000-000000000002")
    assert before.id == renamed.id == infrastructure_stix_id(hunt_id)
    assert before.id.startswith("infrastructure--") and before.id != other
    assert "hunt_id" not in before.to_stix2_object()


def test_a_run_with_hits_builds_the_infrastructure(hunt_event):
    # Given a hunt targeting one intrusion set, and three observables of its hosts
    request = HuntRequest.model_validate(hunt_event({"hunt_type": "infrastructure"}))
    events = [_event("8.8.8.8", ["c2.example.com"], [(CERT_SHA256, CERT_SUBJECT)])]
    observables = collect_infrastructure_observables(
        events, ["IPv4-Addr", "Domain-Name", "X509-Certificate"], 10
    )

    # When the knowledge of the run is built
    objects = build_infrastructure_objects(
        request, 1, FIRST, LAST, observables, "jarm abc", "Shodan"
    )
    stix = [obj if isinstance(obj, dict) else obj.to_stix2_object() for obj in objects]

    # Then the infrastructure, its observables, detection indicators and relationships are built
    assert Counter(obj["type"] for obj in stix) == {
        "infrastructure": 1,
        "ipv4-addr": 1,
        "domain-name": 1,
        "x509-certificate": 1,
        "indicator": 3,
        "relationship": 1 + 3 * 3,
        "observed-data": 3,
    }
    infrastructure = stix[0]
    assert infrastructure["id"] == infrastructure_stix_id("hunt-1")
    assert "(jarm abc): 1 host(s) found on Shodan by hunt run run-1" in (
        infrastructure["description"]
    )
    indicators = [obj for obj in stix if obj["type"] == "indicator"]
    assert {obj["pattern"] for obj in indicators} == {
        "[ipv4-addr:value = '8.8.8.8']",
        "[domain-name:value = 'c2.example.com']",
        f"[x509-certificate:hashes.'SHA-256' = '{CERT_SHA256}']",
    }
    assert {obj["name"] for obj in indicators} == {
        "8.8.8.8",
        "c2.example.com",
        CERT_SUBJECT,
    }
    assert all(obj["x_opencti_detection"] is True for obj in indicators)
    relationships = Counter(
        obj["relationship_type"] for obj in stix if obj["type"] == "relationship"
    )
    assert relationships == {
        "related-to": 1,
        "consists-of": 3,
        "based-on": 3,
        "indicates": 3,
    }


def test_a_certificate_without_subject_is_named_after_its_fingerprint(hunt_event):
    # Given a hunt without target, and a certificate without subject
    request = HuntRequest.model_validate(hunt_event({"targets": []}))
    events = [_event("10.0.0.1", [], [(CERT_SHA256, None)])]
    observables = collect_infrastructure_observables(events, ["X509-Certificate"], 10)

    # When the knowledge of the run is built
    objects = build_infrastructure_objects(
        request, 1, FIRST, LAST, observables, "", "Censys Platform"
    )

    # Then its indicator is named after the fingerprint, with no threat relationship
    (indicator,) = [obj for obj in objects if isinstance(obj, dict)]
    assert indicator["name"] == f"X.509 certificate {CERT_SHA256}"
    relationships = [
        obj.to_stix2_object()["relationship_type"]
        for obj in objects
        if not isinstance(obj, dict) and obj.to_stix2_object()["type"] == "relationship"
    ]
    assert sorted(relationships) == ["based-on", "consists-of"]


def test_a_run_without_hits_builds_nothing(hunt_event):
    # Given/When a run found no host
    request = HuntRequest.model_validate(hunt_event())

    # Then nothing is built
    assert build_infrastructure_objects(request, 0, FIRST, LAST, [], "", "x") == []
