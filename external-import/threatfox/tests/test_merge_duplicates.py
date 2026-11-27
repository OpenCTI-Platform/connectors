"""Tests for ThreatFox._merge_duplicates(): rows mapping to one STIX id.

Builds the bundle objects with process_row() on a bare connector (see
test_process_row_observable.py) and checks the merged result.
"""

from tests.test_process_row_observable import _connector, _row


def _bundle(connector, rows):
    objects = [obj for row in rows for obj in connector.process_row(row)]
    return connector._merge_duplicates(objects)


def _by_type(objects, stix_type):
    return [o for o in objects if o.type == stix_type]


def test_ip_on_several_ports_keeps_every_reference():
    connector = _connector(create_indicators=True)
    rows = [  # newest first, as in the export; the oldest row has no reference
        _row("ip:port", "1.2.3.4:443", reference="https://ref.example/new"),
        _row("ip:port", "1.2.3.4:8080", reference="None"),
    ]

    objects = _bundle(connector, rows)

    [ip] = _by_type(objects, "ipv4-addr")
    [indicator] = _by_type(objects, "indicator")
    assert [r["url"] for r in ip["x_opencti_external_references"]] == [
        "https://ref.example/new"
    ]
    assert [r["url"] for r in indicator["external_references"]] == [
        "https://ref.example/new"
    ]


def test_ip_on_several_ports_gets_a_per_port_description():
    connector = _connector(create_indicators=True)
    rows = [
        _row(
            "ip:port",
            "1.2.3.4:8080",
            threat_type="botnet_cc",
            malware_printable="Cobalt Strike",
        ),
        _row(
            "ip:port",
            "1.2.3.4:443",
            threat_type="payload_delivery",
            malware_printable="Vidar",
        ),
    ]

    objects = _bundle(connector, rows)

    [ip] = _by_type(objects, "ipv4-addr")
    [indicator] = _by_type(objects, "indicator")
    expected = (
        "Activity seen across multiple ports:\n"
        "\n"
        "- 443 (first seen 2024-01-01 00:00 UTC, payload_delivery, Vidar, confidence 75)\n"
        "- 8080 (first seen 2024-01-01 00:00 UTC, botnet_cc, Cobalt Strike, confidence 75)"
    )
    assert ip["x_opencti_description"] == expected
    assert indicator["description"] == expected


def test_ip_on_one_port_keeps_the_single_port_description():
    connector = _connector()
    rows = [_row("ip:port", "1.2.3.4:443"), _row("ip:port", "1.2.3.4:443")]

    [ip] = _by_type(_bundle(connector, rows), "ipv4-addr")

    assert ip["x_opencti_description"] == "Traffic seen on port 443"


def test_merged_object_unions_labels_and_keeps_the_highest_score():
    connector = _connector()
    rows = [
        _row("domain", "bad.example.com", confidence_level=50, threat_type="botnet_cc"),
        _row(
            "domain",
            "bad.example.com",
            confidence_level=90,
            threat_type="payload_delivery",
        ),
    ]

    [domain] = _by_type(_bundle(connector, rows), "domain-name")

    assert domain["x_opencti_score"] == 90
    assert {"botnet_cc", "payload_delivery"} <= set(domain["x_opencti_labels"])


def test_shared_malware_keeps_every_reference():
    connector = _connector()
    rows = [
        _row("domain", "a.example.com", reference="https://ref.example/a"),
        _row("domain", "b.example.com", reference="None"),
        _row("domain", "c.example.com", reference="https://ref.example/c"),
    ]

    objects = _bundle(connector, rows)

    [malware] = _by_type(objects, "malware")
    assert [r["url"] for r in malware["external_references"]] == [
        "https://ref.example/a",
        "https://ref.example/c",
    ]
    assert len(_by_type(objects, "domain-name")) == 3


def test_merge_keeps_ids_unique_and_first_seen_order():
    connector = _connector(create_indicators=True)
    rows = [
        _row("ip:port", "1.2.3.4:443"),
        _row("domain", "bad.example.com"),
        _row("ip:port", "1.2.3.4:80"),
    ]

    objects = _bundle(connector, rows)

    ids = [o.id for o in objects]
    assert len(ids) == len(set(ids))
    assert ids.index(_by_type(objects, "ipv4-addr")[0].id) < ids.index(
        _by_type(objects, "domain-name")[0].id
    )
