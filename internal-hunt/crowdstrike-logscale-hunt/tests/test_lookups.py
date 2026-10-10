import pytest
from conftest import done, mock_falcon_job
from connectors_sdk.connectors.internal_hunt import HuntIoc, IocBatch
from crowdstrike_logscale_hunt.lookups import (
    DOMAIN_FIELDS,
    HASH_FIELDS,
    batch_lookup,
    build_logscale_lookup,
)

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
TEN_AM_MS = "1791021600000"


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
    return build_logscale_lookup(values_batch, batch_lookup(values_batch))


def test_ipv4_lookups_search_the_falcon_and_cps_fields_exactly():
    # Given/When two IPv4 addresses are looked up
    query = lookup_query("IPv4-Addr", "198.51.100.7", "203.0.113.9")

    # Then the Falcon remote address and the CPS source and destination are filtered, case-sensitively
    pattern = r"/^(?:198\.51\.100\.7|203\.0\.113\.9)$/"
    assert query == (
        f"RemoteAddressIP4 = {pattern} or source.ip = {pattern} or destination.ip = {pattern}"
    )


def test_domain_lookups_find_the_domain_and_its_subdomains():
    # Given/When a domain is looked up
    query = lookup_query("Domain-Name", "evil.example.com")

    # Then the Falcon DNS requests and the CPS domain fields match it or a subdomain, ignoring the case
    assert query == " or ".join(
        rf"{field} = /(?:^|\.)(?:evil\.example\.com)$/i" for field in DOMAIN_FIELDS
    )


def test_url_lookups_find_the_url_within_the_url_fields():
    # Given/When a URL with regular expression characters is looked up
    query = lookup_query("Url", "http://evil.example/a/b?x=(1)*")

    # Then it is found within each URL field, case-sensitively, every metacharacter escaped
    pattern = r"/(?:http:\/\/evil\.example\/a\/b\?x=\(1\)\*)/"
    assert query == f"url.original = {pattern} or url.full = {pattern}"


@pytest.mark.parametrize("algorithm", ["MD5", "SHA-1", "SHA-256"])
def test_file_hashes_are_looked_up_in_the_fields_of_their_algorithm(algorithm):
    # Given/When a hash is looked up
    query = lookup_query("StixFile", SHA256, hash_algorithm=algorithm)

    # Then every field of its algorithm is searched, ignoring the case
    assert query == " or ".join(
        f"{field} = /^(?:{SHA256})$/i" for field in HASH_FIELDS[algorithm]
    )


@pytest.mark.parametrize(
    "observable_type, algorithm",
    [
        pytest.param("StixFile", "SHA-512", id="sha512"),
        pytest.param("StixFile", None, id="file_without_hash"),
        pytest.param("User-Account", None, id="user_account"),
    ],
)
def test_types_no_field_holds_are_not_looked_up(observable_type, algorithm):
    # Given/When/Then a type no Falcon or CPS field holds has no lookup
    assert batch_lookup(batch(observable_type, "x", hash_algorithm=algorithm)) is None


def test_slashes_cannot_end_the_regular_expression():
    # Given/When/Then a slash or a backslash in a value stays inside the pattern
    assert lookup_query("Email-Addr", "a/b\\c@evil.example").startswith(
        r"email.from.address = /^(?:a\/b\\c@evil\.example)$/i"
    )


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


def test_indicator_hunt_runs_logscale_lookups_and_reports_each_value(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given recorded Falcon events: a network connection, a DNS request and a process
    mock_falcon_job(
        requests_mock,
        [
            done(
                [
                    {
                        "@timestamp": TEN_AM_MS,
                        "ComputerName": "ws1",
                        "RemoteAddressIP4": "198.51.100.7",
                    }
                ]
            ),
            done(
                [
                    {
                        "@timestamp": TEN_AM_MS,
                        "ComputerName": "ws2",
                        "DomainName": "cdn.evil.example",
                    }
                ]
            ),
            done(
                [
                    {
                        "@timestamp": TEN_AM_MS,
                        "ComputerName": "ws3",
                        "SHA256HashData": SHA256,
                    }
                ]
            ),
        ],
    )
    hunt_event["hunt"].update(INDICATOR_HUNT)

    # When the indicator hunt runs
    connector_factory().process_message(hunt_event)

    # Then one LogScale query job runs per searchable type
    queries = [
        request.json()["queryString"]
        for request in requests_mock.request_history
        if request.method == "POST" and request.url.endswith("/queryjobs")
    ]
    assert [query.split(" = ", 1)[0] for query in queries] == [
        "RemoteAddressIP4",
        "DomainName",
        "SHA256HashData",
    ]
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


def test_indicator_hunt_preview_lists_the_logscale_lookups(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given an indicator hunt preview
    hunt_event["mode"] = "preview"
    hunt_event["hunt"].update(INDICATOR_HUNT)

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then the lookups are shown without querying CrowdStrike
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["query_language"] == "logscale"
    assert r"RemoteAddressIP4 = /^(?:198\.51\.100\.7|203\.0\.113\.9)$/" in (
        kwargs["translated_query"]
    )
