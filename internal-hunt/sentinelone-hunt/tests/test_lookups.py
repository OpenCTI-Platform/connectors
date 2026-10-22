import pytest
from conftest import FORWARD_TAG, QUERIES_URL, done
from connectors_sdk.connectors.internal_hunt import HuntIoc, IocBatch
from sentinelone_hunt.lookups import (
    HASH_FIELDS,
    LOOKUP_FIELDS,
    batch_lookup,
    build_powerquery_lookup,
)

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
TEN_AM_NS = 1791021600000000000


def batch(observable_type, *values, hash_algorithm=None):
    return IocBatch(
        observable_type,
        hash_algorithm,
        tuple(
            HuntIoc(
                key=f"k{index}",
                observable_type=observable_type,
                hash_algorithm=hash_algorithm,
                value=value,
            )
            for index, value in enumerate(values)
        ),
    )


def lookup_query(observable_type, *values, hash_algorithm=None):
    values_batch = batch(observable_type, *values, hash_algorithm=hash_algorithm)
    return build_powerquery_lookup(values_batch, batch_lookup(values_batch))


def test_ip_lookups_search_the_destination_and_source_addresses():
    # Given/When two IPv4 addresses are looked up
    query = lookup_query("IPv4-Addr", "198.51.100.7", "203.0.113.9")

    # Then both address fields are compared with the whole values, without case
    values = '("198.51.100.7","203.0.113.9")'
    assert query == (
        f"dst.ip.address in:anycase {values} or src.ip.address in:anycase {values}"
    )


def test_domain_lookups_find_the_domain_and_its_subdomains():
    # Given/When a domain is looked up
    query = lookup_query("Domain-Name", "evil.example.com")

    # Then the DNS requests match it or one of its subdomains
    assert query == (
        'event.dns.request in:anycase ("evil.example.com") or '
        'event.dns.request ends_with ".evil.example.com"'
    )


def test_hostname_lookups_match_the_whole_name():
    # Given/When/Then a hostname is matched whole
    assert lookup_query("Hostname", "host.example") == (
        'event.dns.request in:anycase ("host.example")'
    )


def test_url_lookups_find_the_url_within_the_url_field():
    # Given/When a URL holding a quote is looked up
    query = lookup_query("Url", 'http://evil.example/a?q="1"')

    # Then it is found within the URL field, the quotes escaped
    assert query == r'url.address contains ("http://evil.example/a?q=\"1\"")'


@pytest.mark.parametrize("algorithm", ["MD5", "SHA-1", "SHA-256"])
def test_file_hashes_are_looked_up_in_the_fields_of_their_algorithm(algorithm):
    # Given/When a hash is looked up
    query = lookup_query("StixFile", SHA256, hash_algorithm=algorithm)

    # Then every field of its algorithm is searched
    assert query == " or ".join(
        f'{field} in:anycase ("{SHA256}")' for field in HASH_FIELDS[algorithm]
    )


@pytest.mark.parametrize(
    "observable_type, algorithm",
    [
        pytest.param("StixFile", "SHA-512", id="sha512"),
        pytest.param("StixFile", None, id="file_without_hash"),
        pytest.param("Email-Addr", None, id="email"),
        pytest.param("Mac-Addr", None, id="mac"),
    ],
)
def test_types_no_field_holds_are_not_looked_up(observable_type, algorithm):
    # Given/When/Then a type no EDR field holds has no lookup
    assert batch_lookup(batch(observable_type, "x", hash_algorithm=algorithm)) is None


def test_lookup_fields_cover_every_lookup():
    # Given/When/Then every field a lookup reads is listed once
    assert len(LOOKUP_FIELDS) == len(set(LOOKUP_FIELDS))
    assert {"dst.ip.address", "event.dns.request", "url.address"} <= set(LOOKUP_FIELDS)
    assert set(HASH_FIELDS["SHA-256"]) <= set(LOOKUP_FIELDS)


INDICATOR_HUNT = {
    "hunt_type": "indicators",
    "sigma_rule": None,
    "iocs": [
        {"key": "k-ip", "observable_type": "IPv4-Addr", "value": "198.51.100.7"},
        {"key": "k-unseen-ip", "observable_type": "IPv4-Addr", "value": "203.0.113.9"},
        {"key": "k-domain", "observable_type": "Domain-Name", "value": "evil.example"},
        {
            "key": "k-sha256",
            "observable_type": "StixFile",
            "hash_algorithm": "SHA-256",
            "value": SHA256,
        },
        {
            "key": "k-sha512",
            "observable_type": "StixFile",
            "hash_algorithm": "SHA-512",
            "value": "a" * 128,
        },
    ],
}


def _answer(columns, row, query_id):
    return {
        "json": done(columns, [row], query_id=query_id),
        "headers": {"X-Dataset-Query-Forward-Tag": FORWARD_TAG},
    }


def test_indicator_hunt_runs_powerquery_lookups_and_reports_each_value(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given recorded EDR events: a network connection, a DNS request and a process
    requests_mock.post(
        QUERIES_URL,
        [
            _answer(
                ["timestamp", "event.id", "endpoint.name", "dst.ip.address"],
                [TEN_AM_NS, "event-1", "ws1", "198.51.100.7"],
                "q1",
            ),
            _answer(
                ["timestamp", "endpoint.name", "event.dns.request"],
                [TEN_AM_NS, "ws2", "cdn.evil.example"],
                "q2",
            ),
            _answer(
                ["timestamp", "endpoint.name", "src.process.image.sha256"],
                [TEN_AM_NS, "ws3", SHA256],
                "q3",
            ),
        ],
    )
    for query_id in ("q1", "q2", "q3"):
        requests_mock.delete(f"{QUERIES_URL}/{query_id}", status_code=204)
    hunt_event["hunt"].update(INDICATOR_HUNT)

    # When the indicator hunt runs
    connector_factory().process_message(hunt_event)

    # Then one PowerQuery runs per searchable type, on the EDR telemetry, with
    # its field names checked
    launches = [r.json() for r in requests_mock.request_history if r.method == "POST"]
    assert [launch["scheme"] for launch in launches] == ["edr", "edr", "edr"]
    filters = [
        launch["pq"]["query"].split(" and (", 1)[1].split(" ", 1)[0]
        for launch in launches
    ]
    assert filters == ["dst.ip.address", "event.dns.request", "tgt.file.sha256"]
    # And every value is seen, not seen, or not searched when no field holds it
    kwargs = helper.report_hunt_run.call_args.kwargs
    by_key = {item["key"]: item for item in kwargs["ioc_results"]}
    assert (by_key["k-ip"]["seen"], by_key["k-ip"]["hosts"]) == (True, ["ws1"])
    assert (by_key["k-unseen-ip"]["seen"], by_key["k-unseen-ip"]["searched"]) == (
        False,
        True,
    )
    assert by_key["k-domain"]["hosts"] == ["ws2"]
    assert by_key["k-sha256"]["hosts"] == ["ws3"]
    assert by_key["k-sha512"]["searched"] is False
    # And a hit is known by the id SentinelOne gives its event, never shown as evidence
    hit = next(item for item in kwargs["hits_sample"] if item["host"] == "ws1")
    assert hit["event_id"] == "event-1"
    assert all(item["field"] != "event.id" for item in kwargs["evidence_sample"])


def test_indicator_hunt_preview_lists_the_powerquery_lookups(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given an indicator hunt preview
    hunt_event["mode"] = "preview"
    hunt_event["hunt"].update(INDICATOR_HUNT)

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then the lookups are shown without querying SentinelOne
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["query_language"] == "powerquery"
    assert 'dst.ip.address in:anycase ("198.51.100.7","203.0.113.9")' in (
        kwargs["translated_query"]
    )
