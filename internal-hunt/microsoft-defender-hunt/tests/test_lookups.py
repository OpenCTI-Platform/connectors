import re

import pytest
from conftest import HUNTING_URL, answer, hunting_queries
from connectors_sdk.connectors.internal_hunt import HuntIoc, HuntTimeWindow, IocBatch
from microsoft_defender_hunt.lookups import (
    HASH_COLUMNS,
    LOOKUPS,
    TABLE_COLUMNS,
    batch_lookups,
    build_kql_lookup,
    kql_regex,
    kql_string,
)
from sigma.pipelines.microsoftxdr.tables import MICROSOFT_XDR_TABLES

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
WINDOW = HuntTimeWindow(start="2026-10-03T00:00:00Z", end="2026-10-04T00:00:00Z")
SCHEMA = {
    table: {column.strip() for column in columns}
    for table, columns in MICROSOFT_XDR_TABLES.items()
}


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


def lookup_query(observable_type, *values, hash_algorithm=None, window=None):
    values_batch = batch(observable_type, *values, hash_algorithm=hash_algorithm)
    return build_kql_lookup(values_batch, batch_lookups(values_batch), window)


def _regex_of(query, column):
    """Return the Python form of the regular expression a lookup matches a column with."""
    patterns = set(re.findall(rf'{column} matches regex @"((?:[^"]|"")*)"', query))
    [pattern] = patterns
    return re.compile(pattern.replace('""', '"'))


def test_every_projected_column_is_a_column_of_its_table():
    # Given/When/Then every column a lookup keeps exists in the advanced hunting
    # schema of the Sigma pipeline
    assert {
        table: sorted(set(columns) - SCHEMA[table])
        for table, columns in TABLE_COLUMNS.items()
        if set(columns) - SCHEMA[table]
    } == {}


def test_every_searched_column_is_projected():
    # Given every lookup, hashes included
    lookups = [lookup for found in LOOKUPS.values() for lookup in found]
    for algorithm in HASH_COLUMNS:
        lookups.extend(batch_lookups(batch("StixFile", "x", hash_algorithm=algorithm)))

    # When/Then the columns searched are columns of their table
    assert [
        (lookup.table, column)
        for lookup in lookups
        for column in lookup.columns
        if column not in SCHEMA[lookup.table]
    ] == []


def test_ip_lookup_unions_one_leg_per_table():
    # Given/When two IPv4 addresses are looked up over a run window
    query = lookup_query("IPv4-Addr", "198.51.100.7", "203.0.113.9", window=WINDOW)

    # Then one fuzzy union searches each table holding addresses, case-insensitively
    assert query.startswith("union isfuzzy=true\n(DeviceNetworkEvents\n")
    assert query.count("\n| extend SourceTable = ") == len(LOOKUPS["IPv4-Addr"])
    first_leg = query.split(",\n(")[0]
    assert first_leg == (
        "union isfuzzy=true\n"
        "(DeviceNetworkEvents\n"
        "| where Timestamp between (datetime(2026-10-03T00:00:00.000Z) .. "
        "datetime(2026-10-04T00:00:00.000Z))\n"
        '| where RemoteIP in~ ("198.51.100.7", "203.0.113.9") or '
        'LocalIP in~ ("198.51.100.7", "203.0.113.9")\n'
        "| project "
        + ", ".join(TABLE_COLUMNS["DeviceNetworkEvents"]).replace(
            "ReportId", "ReportId = tostring(ReportId)"
        )
        + "\n"
        '| extend SourceTable = "DeviceNetworkEvents")'
    )
    # And the report id is a string in every leg, so that the union keeps one column
    assert query.count("ReportId = tostring(ReportId)") == len(LOOKUPS["IPv4-Addr"])
    assert 'SenderIPv4 in~ ("198.51.100.7", "203.0.113.9")' in query


def test_ipv6_lookups_search_the_ipv6_sender():
    # Given/When/Then an IPv6 address is searched in the IPv6 sender of emails
    query = lookup_query("IPv6-Addr", "2001:db8::7")
    assert 'SenderIPv6 in~ ("2001:db8::7")' in query
    assert "SenderIPv4 in~" not in query


@pytest.mark.parametrize(
    "url, expected",
    [
        pytest.param("https://evil.example/a", True, id="url"),
        pytest.param("https://cdn.EVIL.example:8443/x", True, id="subdomain_port"),
        pytest.param("evil.example", True, id="host_only"),
        pytest.param("http://user@evil.example?q=1", True, id="userinfo_query"),
        pytest.param("https://notevil.example/", False, id="other_domain"),
        pytest.param("https://evil.example.attacker.net/", False, id="prefix"),
        pytest.param("https://good.example/?r=evil.examples", False, id="longer"),
    ],
)
def test_domain_lookups_find_the_domain_and_its_subdomains_in_urls(url, expected):
    # Given/When a domain is looked up in URL columns
    query = lookup_query("Domain-Name", "evil.example")

    # Then the term index narrows the search and the expression keeps the domain
    # and its subdomains only
    assert 'RemoteUrl has_any ("evil.example")' in query
    assert bool(_regex_of(query, "RemoteUrl").search(url)) is expected


@pytest.mark.parametrize(
    "domain, expected",
    [
        pytest.param("evil.example", True, id="domain"),
        pytest.param("mail.evil.example", True, id="subdomain"),
        pytest.param("notevil.example", False, id="other_domain"),
    ],
)
def test_domain_lookups_find_the_domain_in_domain_columns(domain, expected):
    # Given/When/Then the sender domain of an email is the domain or a subdomain
    query = lookup_query("Domain-Name", "evil.example")
    assert bool(_regex_of(query, "SenderFromDomain").search(domain)) is expected


@pytest.mark.parametrize(
    "url, expected",
    [
        pytest.param("http://c2-node-1:8080/beacon", True, id="url"),
        pytest.param("c2-node-1", True, id="host_only"),
        pytest.param("https://x.c2-node-1/", False, id="subdomain"),
    ],
)
def test_hostname_lookups_find_the_host_itself(url, expected):
    # Given/When/Then a host name is found as the host of a URL, not as a parent domain
    query = lookup_query("Hostname", "c2-node-1")
    assert bool(_regex_of(query, "RemoteUrl").search(url)) is expected
    assert 'UrlDomain in~ ("c2-node-1")' in query


def test_url_lookups_find_the_url_within_the_url_columns():
    # Given/When a URL with quotes is looked up
    query = lookup_query("Url", 'http://evil.example/a?x="1"')

    # Then it is found within each URL column, case-sensitively, every quote escaped
    assert 'RemoteUrl contains_cs "http://evil.example/a?x=\\"1\\""' in query
    assert query.count("contains_cs") == 7


def test_email_lookups_search_senders_and_recipients():
    # Given/When/Then an address is searched in the senders and recipients of emails
    query = lookup_query("Email-Addr", "ceo@evil.example")
    assert query.startswith("union isfuzzy=true\n(EmailEvents\n")
    for column in (
        "SenderFromAddress",
        "SenderMailFromAddress",
        "RecipientEmailAddress",
    ):
        assert f'{column} in~ ("ceo@evil.example")' in query


@pytest.mark.parametrize(
    "algorithm, column", [("MD5", "MD5"), ("SHA-1", "SHA1"), ("SHA-256", "SHA256")]
)
def test_file_hashes_are_looked_up_in_the_columns_of_their_algorithm(algorithm, column):
    # Given/When a hash is looked up
    query = lookup_query("StixFile", SHA256, hash_algorithm=algorithm)

    # Then the files and the processes that acted are searched with the column of
    # the algorithm, and SHA-256 hashes in email attachments too
    assert query.startswith("union isfuzzy=true\n(DeviceProcessEvents\n")
    assert f'{column} in~ ("{SHA256}") or InitiatingProcess{column} in~' in query
    assert ("(EmailAttachmentInfo\n" in query) is (algorithm == "SHA-256")


@pytest.mark.parametrize(
    "observable_type, algorithm",
    [
        pytest.param("StixFile", "SHA-512", id="sha512"),
        pytest.param("StixFile", None, id="file_without_hash"),
        pytest.param("User-Account", None, id="user_account"),
        pytest.param("Mac-Addr", None, id="mac"),
    ],
)
def test_types_no_column_holds_are_not_looked_up(observable_type, algorithm):
    # Given/When/Then a type advanced hunting stores in no column has no lookup
    assert batch_lookups(batch(observable_type, "x", hash_algorithm=algorithm)) is None


def test_literals_are_escaped():
    # Given/When/Then quotes, backslashes and control characters cannot end a literal
    assert kql_string('a"b\\c\nd\x01') == r'"a\"b\\c\nd"'
    assert kql_regex('a"b') == '@"a""b"'


def test_regex_values_are_matched_literally():
    # Given/When a domain with regular expression characters is looked up
    query = lookup_query("Domain-Name", "a+b.example")

    # Then they are escaped in the expression
    regex = _regex_of(query, "RemoteUrl")
    assert regex.search("https://a+b.example/")
    assert not regex.search("https://aab.example/")


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

NETWORK_COLUMNS = [
    ("Timestamp", "DateTime"),
    ("DeviceId", "String"),
    ("DeviceName", "String"),
    ("ReportId", "Int64"),
    ("InitiatingProcessAccountName", "String"),
    ("InitiatingProcessFileName", "String"),
    ("RemoteIP", "String"),
    ("RemoteUrl", "String"),
    ("SHA256", "String"),
    ("NetworkMessageId", "String"),
    ("RecipientEmailAddress", "String"),
    ("SourceTable", "String"),
]


def test_indicator_hunt_runs_one_query_per_type_and_reports_each_value(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given advanced hunting events holding the IP, a subdomain and the hash
    requests_mock.post(
        HUNTING_URL,
        [
            {
                "json": answer(
                    NETWORK_COLUMNS,
                    [
                        [
                            "2026-10-03T10:00:00.1234567Z",
                            "dev-1",
                            "ws1.corp.example",
                            11,
                            "alice",
                            "curl.exe",
                            "198.51.100.7",
                            None,
                            None,
                            None,
                            None,
                            "DeviceNetworkEvents",
                        ]
                    ],
                )
            },
            {
                "json": answer(
                    NETWORK_COLUMNS,
                    [
                        [
                            "2026-10-03T11:00:00Z",
                            "dev-2",
                            "ws2.corp.example",
                            12,
                            "bob",
                            "chrome.exe",
                            None,
                            "https://cdn.evil.example/x",
                            None,
                            None,
                            None,
                            "DeviceNetworkEvents",
                        ]
                    ],
                )
            },
            {
                "json": answer(
                    NETWORK_COLUMNS,
                    [
                        [
                            "2026-10-03T12:00:00Z",
                            None,
                            None,
                            13,
                            None,
                            None,
                            None,
                            None,
                            SHA256,
                            "msg-1",
                            "carol@corp.example",
                            "EmailAttachmentInfo",
                        ]
                    ],
                )
            },
        ],
    )
    hunt_event["hunt"].update(INDICATOR_HUNT)

    # When the indicator hunt runs
    connector_factory().process_message(hunt_event)

    # Then one advanced hunting query runs per searchable type, over the run window
    queries = hunting_queries(requests_mock)
    assert len(queries) == 3
    assert 'RemoteIP in~ ("198.51.100.7", "203.0.113.9")' in queries[0]
    assert 'RemoteUrl has_any ("evil.example")' in queries[1]
    assert f'SHA256 in~ ("{SHA256}")' in queries[2]
    assert all(
        "Timestamp between (datetime(2026-10-03T00:00:00.000Z)" in query
        for query in queries
    )
    assert requests_mock.last_request.json()["Timespan"] == (
        "2026-10-03T00:00:00.000Z/2026-10-04T00:00:00.000Z"
    )
    # And every value is seen, not seen, or not searched when no column holds it
    kwargs = helper.report_hunt_run.call_args.kwargs
    by_key = {item["key"]: item for item in kwargs["ioc_results"]}
    assert (by_key["k-ip"]["seen"], by_key["k-ip"]["hosts"]) == (
        True,
        ["ws1.corp.example"],
    )
    assert (by_key["k-unseen-ip"]["seen"], by_key["k-unseen-ip"]["searched"]) == (
        False,
        True,
    )
    assert by_key["k-domain"]["hosts"] == ["ws2.corp.example"]
    assert by_key["k-sha256"]["first_seen"].startswith("2026-10-03T12:00:00")
    assert by_key["k-sha512"]["searched"] is False
    # And each hit names its machine, its user, the column holding the value and
    # the id of its event: the report id within its device or message, and its time
    hits = kwargs["hits_sample"]
    assert [
        (hit["host"], hit["user"], [item["field"] for item in hit["matched"]])
        for hit in hits
    ] == [
        ("ws1.corp.example", "alice", ["RemoteIP"]),
        ("ws2.corp.example", "bob", ["RemoteUrl"]),
        (None, "carol@corp.example", ["SHA256"]),
    ]
    assert [hit["event_id"] for hit in hits] == [
        "dev-1|11|2026-10-03T10:00:00.1234567Z",
        "dev-2|12|2026-10-03T11:00:00Z",
        "msg-1|carol@corp.example|13|2026-10-03T12:00:00Z",
    ]
    assert len(kwargs["hit_keys"]) == 3
    # And the bookkeeping columns are never shown as evidence
    fields = {item["field"] for item in kwargs["evidence_sample"]}
    assert not fields & {"HuntEventId", "ReportId", "DeviceId", "NetworkMessageId"}


def test_indicator_hunt_preview_lists_the_lookups(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given an indicator hunt preview
    hunt_event["mode"] = "preview"
    hunt_event["hunt"].update(INDICATOR_HUNT)

    # When it is processed
    connector_factory().process_message(hunt_event)

    # Then the lookups are shown without querying advanced hunting
    assert hunting_queries(requests_mock) == []
    kwargs = helper.report_hunt_run.call_args.kwargs
    assert kwargs["query_language"] == "kql"
    assert 'RemoteIP in~ ("198.51.100.7", "203.0.113.9")' in kwargs["translated_query"]
