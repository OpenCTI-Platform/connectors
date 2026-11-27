"""Tests for ThreatFox._merge_duplicates() and _describe_ports().

Builds the bundle objects with process_row() on a bare connector (see
test_process_row_observable.py) and checks the merged result. Stored
descriptions come from the mocked helper.api list calls.
"""

import stix2
from pycti import Indicator

from tests.test_process_row_observable import _connector, _row

IP_ID = stix2.IPv4Address(value="1.2.3.4").id
INDICATOR_ID = Indicator.generate_id("[ipv4-addr:value = '1.2.3.4']")


def _bundle(connector, rows):
    objects = [obj for row in rows for obj in connector.process_row(row)]
    return connector._describe_ports(connector._merge_duplicates(objects))


def _by_type(objects, stix_type):
    return [o for o in objects if o.type == stix_type]


def _stored(connector, observable=None, indicator=None):
    """Make OpenCTI hold these descriptions for 1.2.3.4 and its indicator."""
    connector.helper.api.stix_cyber_observable.list.return_value = (
        [{"standard_id": IP_ID, "x_opencti_description": observable}]
        if observable
        else []
    )
    connector.helper.api.indicator.list.return_value = (
        [{"standard_id": INDICATOR_ID, "description": indicator}] if indicator else []
    )


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
        "### ThreatFox\n"
        "\n"
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

    assert ip["x_opencti_description"] == "### ThreatFox\n\nTraffic seen on port 443"


def test_existing_description_is_kept_above_the_threatfox_section():
    connector = _connector(create_indicators=True)
    _stored(connector, observable="Seen in incident 42.", indicator="Block at edge.")

    objects = _bundle(connector, [_row("ip:port", "1.2.3.4:443")])

    [ip] = _by_type(objects, "ipv4-addr")
    [indicator] = _by_type(objects, "indicator")
    assert ip["x_opencti_description"] == (
        "Seen in incident 42.\n\n### ThreatFox\n\nTraffic seen on port 443"
    )
    assert indicator["description"] == (
        "Block at edge.\n\n### ThreatFox\n\nTraffic seen on port 443"
    )


def test_rerun_replaces_only_the_threatfox_section():
    connector = _connector()
    _stored(
        connector,
        observable=(
            "Seen in incident 42.\n\n### ThreatFox\n\nTraffic seen on port 443"
            "\n\n### Notes\n\nOwned by team X."
        ),
    )

    [ip] = _by_type(_bundle(connector, [_row("ip:port", "1.2.3.4:443")]), "ipv4-addr")

    assert ip["x_opencti_description"] == (
        "Seen in incident 42.\n\n### Notes\n\nOwned by team X."
        "\n\n### ThreatFox\n\nTraffic seen on port 443"
    )


def test_ports_from_earlier_runs_are_kept():
    connector = _connector()
    _stored(connector, observable="Traffic seen on port 80")  # pre-section build
    rows = [_row("ip:port", "1.2.3.4:443", malware_printable="Vidar")]

    [ip] = _by_type(_bundle(connector, rows), "ipv4-addr")

    assert ip["x_opencti_description"] == (
        "### ThreatFox\n"
        "\n"
        "Activity seen across multiple ports:\n"
        "\n"
        "- 80\n"
        "- 443 (first seen 2024-01-01 00:00 UTC, botnet_cc, Vidar, confidence 75)"
    )


def test_unheaded_port_text_below_a_user_note_is_replaced_not_kept():
    connector = _connector()
    old_list = (
        "Activity seen across multiple ports:\n\n"
        "- 80 (first seen 2023-01-01 00:00 UTC, botnet_cc, Old, confidence 50)\n"
        "- 443 (first seen 2023-01-01 00:00 UTC, botnet_cc, Old, confidence 50)"
    )
    _stored(
        connector,
        observable=(
            f"Test note.\n\n{old_list}\n\n### ThreatFox\n\n{old_list}\n\nMore notes."
        ),
    )

    [ip] = _by_type(_bundle(connector, [_row("ip:port", "1.2.3.4:443")]), "ipv4-addr")

    description = ip["x_opencti_description"]
    assert description.startswith("Test note.\n\nMore notes.\n\n### ThreatFox\n\n")
    assert description.count("Activity seen across multiple ports:") == 1
    assert description.count("- 80 (") == 1


def test_this_run_updates_a_port_already_listed():
    connector = _connector()
    _stored(
        connector,
        observable=(
            "### ThreatFox\n\nActivity seen across multiple ports:\n\n"
            "- 80 (first seen 2023-01-01 00:00 UTC, botnet_cc, Old, confidence 50)\n"
            "- 443 (first seen 2023-01-01 00:00 UTC, botnet_cc, Old, confidence 50)"
        ),
    )
    rows = [_row("ip:port", "1.2.3.4:443", malware_printable="New")]

    [ip] = _by_type(_bundle(connector, rows), "ipv4-addr")

    assert ip["x_opencti_description"].endswith(
        "- 80 (first seen 2023-01-01 00:00 UTC, botnet_cc, Old, confidence 50)\n"
        "- 443 (first seen 2024-01-01 00:00 UTC, botnet_cc, New, confidence 75)"
    )


def test_lookup_filters_on_standard_id():
    connector = _connector(create_indicators=True)
    rows = [_row("ip:port", "1.2.3.4:443"), _row("domain", "bad.example.com")]

    _bundle(connector, rows)

    observable_call = connector.helper.api.stix_cyber_observable.list.call_args
    indicator_call = connector.helper.api.indicator.list.call_args
    assert observable_call.kwargs["filters"]["filters"] == [
        {"key": "standard_id", "values": [IP_ID]}
    ]
    assert indicator_call.kwargs["filters"]["filters"] == [
        {"key": "standard_id", "values": [INDICATOR_ID]}
    ]


def test_no_lookup_without_ip_rows():
    connector = _connector(create_indicators=True)

    _bundle(connector, [_row("domain", "bad.example.com")])

    connector.helper.api.stix_cyber_observable.list.assert_not_called()
    connector.helper.api.indicator.list.assert_not_called()


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
