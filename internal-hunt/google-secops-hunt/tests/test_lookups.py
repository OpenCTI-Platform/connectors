import json
from importlib import resources
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import UDM_SEARCH_URL, udm_event
from connectors_sdk.connectors.internal_hunt import HuntIoc, IocBatch
from google_secops_hunt.lookups import (
    FILE_NOUNS,
    HASH_FIELDS,
    LOOKUPS,
    batch_lookup,
    build_udm_lookup,
    udm_string,
)
from sigma.pipelines.secops.validators import is_valid_udm_field

UDM_SCHEMA = json.loads(
    resources.files("sigma.pipelines.secops")
    .joinpath("udm_field_schema.json")
    .read_text(encoding="utf-8")
)
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


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
    return build_udm_lookup(values_batch, batch_lookup(values_batch))


def test_every_lookup_field_is_a_udm_field():
    # Given every UDM field the lookups search
    fields = {field for lookup in LOOKUPS.values() for field in lookup.fields}
    fields |= {
        f"{noun}.{field}" for noun in FILE_NOUNS for field in HASH_FIELDS.values()
    }

    # When/Then each is valid for the UDM schema of the Sigma pipeline, which rejects unknown fields
    assert [
        field for field in sorted(fields) if not is_valid_udm_field(field, UDM_SCHEMA)
    ] == []


@pytest.mark.parametrize(
    "observable_type, values, expected",
    [
        pytest.param(
            "IPv4-Addr",
            ("198.51.100.7", "203.0.113.9"),
            'ip = "198.51.100.7" OR ip = "203.0.113.9"',
            id="ipv4",
        ),
        pytest.param(
            "IPv6-Addr", ("2001:db8::7",), 'ip = "2001:db8::7" nocase', id="ipv6"
        ),
        pytest.param(
            "Domain-Name",
            ("evil.example.com",),
            r"domain = /(^|\.)evil\.example\.com$/ nocase",
            id="domain_and_subdomains",
        ),
        pytest.param(
            "Hostname", ("c2-node-1",), 'hostname = "c2-node-1" nocase', id="hostname"
        ),
        pytest.param(
            "Email-Addr",
            ("ceo@evil.example",),
            'email = "ceo@evil.example" nocase',
            id="email",
        ),
    ],
)
def test_lookups_search_the_grouped_udm_fields(observable_type, values, expected):
    # Given/When/Then the values are compared to the grouped UDM fields of their type
    assert lookup_query(observable_type, *values) == expected


def test_url_lookups_find_the_url_within_the_url_fields():
    # Given/When a URL with regular expression characters is looked up
    query = lookup_query("Url", "http://evil.example/a/b?x=(1)")

    # Then it is found within each URL field, case-sensitively, every special character escaped
    pattern = r"/http:\/\/evil\.example\/a\/b\?x=\(1\)/"
    assert query == " OR ".join(
        f"{field} = {pattern}"
        for field in (
            "target.url",
            "principal.url",
            "src.url",
            "network.http.referral_url",
        )
    )


@pytest.mark.parametrize(
    "algorithm, field", [("MD5", "md5"), ("SHA-1", "sha1"), ("SHA-256", "sha256")]
)
def test_file_hashes_are_looked_up_in_the_fields_of_their_algorithm(algorithm, field):
    # Given/When a hash is looked up
    query = lookup_query("StixFile", SHA256, hash_algorithm=algorithm)

    # Then every file field of its algorithm is searched, the launched process first
    clauses = query.split(" OR ")
    assert clauses[0] == f'target.process.file.{field} = "{SHA256}" nocase'
    assert len(clauses) == len(FILE_NOUNS)


@pytest.mark.parametrize(
    "observable_type, algorithm",
    [
        pytest.param("StixFile", "SHA-512", id="sha512"),
        pytest.param("StixFile", "SSDEEP", id="ssdeep"),
        pytest.param("StixFile", None, id="file_without_hash"),
        pytest.param("User-Account", None, id="user_account"),
    ],
)
def test_types_udm_holds_in_no_field_are_not_looked_up(observable_type, algorithm):
    # Given/When/Then a type UDM stores in no field has no lookup
    assert batch_lookup(batch(observable_type, "x", hash_algorithm=algorithm)) is None


def test_string_values_are_escaped():
    # Given/When/Then quotes and backslashes cannot end the string literal
    assert udm_string('a"b\\c') == r'"a\"b\\c"'


INDICATOR_HUNT = {
    "hunt_type": "indicators",
    "sigma_rule": None,
    "iocs": [
        {
            "key": "k-ip",
            "observable_type": "IPv4-Addr",
            "value": "198.51.100.7",
            "sources": [
                {
                    "standard_id": "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
                    "entity_type": "Indicator",
                }
            ],
        },
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


def test_indicator_hunt_runs_udm_searches_and_reports_each_value(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given a connector translating Sigma rules into YARA-L, and recorded UDM search events
    requests_mock.get(
        UDM_SEARCH_URL,
        json={
            "events": [
                udm_event(
                    "2026-10-03T10:00:00Z",
                    principal={"hostname": "ws1", "ip": ["10.0.0.5"]},
                    target={"ip": ["198.51.100.7"]},
                ),
                udm_event(
                    "2026-10-03T11:00:00Z",
                    principal={"hostname": "ws2"},
                    network={"dns": {"questions": [{"name": "cdn.evil.example"}]}},
                ),
                udm_event(
                    "2026-10-03T12:00:00Z",
                    principal={"hostname": "ws3", "user": {"userid": "carol"}},
                    target={"process": {"file": {"sha256": SHA256}}},
                ),
            ]
        },
    )
    connector = connector_factory({"google_secops_hunt": {"query_language": "yara-l"}})
    hunt_event["hunt"].update(INDICATOR_HUNT)

    # When the indicator hunt runs
    connector.process_message(hunt_event)

    # Then one UDM search runs per searchable type, never a YARA-L rule
    queries = [
        parse_qs(urlparse(request.url).query)["query"][0]
        for request in requests_mock.request_history
    ]
    assert queries == [
        'ip = "198.51.100.7" OR ip = "203.0.113.9"',
        r"domain = /(^|\.)evil\.example$/ nocase",
        " OR ".join(f'{noun}.sha256 = "{SHA256}" nocase' for noun in FILE_NOUNS),
    ]
    # And every value is seen, not seen, or not searched when UDM cannot hold it
    kwargs = helper.report_hunt_run.call_args.kwargs
    by_key = {item["key"]: item for item in kwargs["ioc_results"]}
    assert (by_key["k-ip"]["seen"], by_key["k-ip"]["hosts"]) == (True, ["ws1"])
    assert (by_key["k-unseen-ip"]["seen"], by_key["k-unseen-ip"]["searched"]) == (
        False,
        True,
    )
    assert by_key["k-domain"]["seen"] is True
    assert by_key["k-sha256"]["first_seen"].startswith("2026-10-03T12:00:00")
    assert by_key["k-sha512"]["searched"] is False
    assert "does not look up StixFile" in by_key["k-sha512"]["reason"]
    # And each hit names the UDM field holding the value
    assert [
        (hit["host"], [item["field"] for item in hit["matched"]])
        for hit in kwargs["hits_sample"]
    ] == [
        ("ws1", ["target.ip"]),
        ("ws2", ["network.dns.questions"]),
        ("ws3", ["target.process.file.sha256"]),
    ]


def test_indicator_hunt_preview_lists_the_udm_searches(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given an indicator hunt preview
    hunt_event["mode"] = "preview"
    hunt_event["hunt"].update(INDICATOR_HUNT)

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then the lookups are shown without querying SecOps
    assert requests_mock.call_count == 0
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["query_language"] == "udm"
    assert 'ip = "198.51.100.7"' in kwargs["translated_query"]
