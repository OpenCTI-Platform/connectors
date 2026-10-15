import pytest
from conftest import NAMESPACE
from connectors_sdk.connectors.internal_hunt import HuntIoc, IocBatch
from splunk_hunt.cim import (
    attributed_host,
    event_address,
    host_eval_spl,
    sourcetype_class,
)
from splunk_hunt.connector import build_ioc_lookup


@pytest.mark.parametrize(
    "row, expected",
    [
        # Firewall, outbound: the internal source, not the appliance
        (
            {
                "sourcetype": "pan:traffic",
                "host": "pa-fw01",
                "src_ip": "10.1.4.22",
                "dest_ip": "203.0.113.9",
            },
            "10.1.4.22",
        ),
        # Firewall, inbound: the internal destination, not the attacker
        (
            {
                "sourcetype": "pan:traffic",
                "host": "pa-fw01",
                "src_ip": "198.51.100.4",
                "dest_ip": "10.1.2.3",
            },
            "10.1.2.3",
        ),
        # Explicit inbound direction wins over the address ranges
        (
            {
                "sourcetype": "cisco:asa",
                "host": "asa1",
                "src": "203.0.113.1",
                "dest": "198.51.100.2",
                "direction": "inbound",
            },
            "198.51.100.2",
        ),
        # Proxy and DNS (CIM src/dest)
        (
            {
                "sourcetype": "bluecoat:proxysg:access:syslog",
                "host": "proxy-sg02",
                "src": "10.1.7.91",
                "dest": "evil.example.com",
            },
            "10.1.7.91",
        ),
        (
            {
                "sourcetype": "infoblox:dns",
                "host": "dns-ib01",
                "src": "10.1.9.5",
                "query": "evil.example.com",
            },
            "10.1.9.5",
        ),
        # Appliance event without peers: the appliance itself
        ({"sourcetype": "pan:system", "host": "pa-fw01"}, "pa-fw01"),
        # Forwarded Windows logs: the reporting computer, not the collector
        (
            {
                "sourcetype": "XmlWinEventLog:Security",
                "host": "wef-collector",
                "ComputerName": "WS-0042",
            },
            "WS-0042",
        ),
        ({"sourcetype": "WinEventLog:Security", "host": "WS-0042"}, "WS-0042"),
        # Unknown sourcetype: unchanged behavior
        ({"sourcetype": "custom:app", "host": "app01", "src": "10.0.0.1"}, "app01"),
    ],
)
def test_attributed_host(row, expected):
    assert attributed_host(row) == expected


def test_sourcetype_class():
    assert sourcetype_class("PAN:Traffic") == "network"
    assert (
        sourcetype_class("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
        == "endpoint"
    )
    assert sourcetype_class("custom") is None
    assert sourcetype_class(None) is None


def test_event_address_is_unique_across_indexes():
    assert event_address({"index": "a", "_cd": "12:345"}) != event_address(
        {"index": "b", "_cd": "12:345"}
    )
    assert event_address({"_cd": "12:345"}) is None


def test_host_eval_spl_mirrors_python_rules():
    spl = host_eval_spl()
    assert spl.startswith('case(match(lower(sourcetype), "^(pan:')
    assert 'lower(direction)=="inbound"' in spl
    assert 'cidrmatch("10.0.0.0/8", coalesce(src_ip, src))' in spl
    assert "coalesce(ComputerName, Computer, dest_nt_host, host)" in spl
    assert spl.endswith("true(), host)")
    assert spl.count("(") == spl.count(")")


def test_ioc_lookup_uses_the_attribution_expression():
    batch = IocBatch(
        "IPv4-Addr",
        None,
        (HuntIoc(key="k1", observable_type="IPv4-Addr", value="198.51.100.7"),),
    )
    assert '| eval host=coalesce(host, "")' in build_ioc_lookup(batch)
    query = build_ioc_lookup(batch, host_expression=host_eval_spl())
    assert f'| eval host=coalesce({host_eval_spl()}, "")' in query


def test_connector_ioc_query_follows_the_setting(connector_factory):
    batch = IocBatch(
        "IPv4-Addr",
        None,
        (HuntIoc(key="k1", observable_type="IPv4-Addr", value="198.51.100.7"),),
    )
    assert "cidrmatch" in connector_factory().ioc_query(batch).query
    raw = connector_factory({"splunk_hunt": {"host_attribution": "raw"}})
    assert "cidrmatch" not in raw.ioc_query(batch).query


FIREWALL_ROWS = [
    {
        "_time": "2026-10-03T10:00:00Z",
        "sourcetype": "pan:traffic",
        "host": "pa-fw01",
        "src_ip": "10.1.4.22",
        "dest_ip": "203.0.113.9",
        "index": "netfw",
        "_cd": "12:345",
    },
    {
        "_time": "2026-10-03T10:05:00Z",
        "sourcetype": "pan:traffic",
        "host": "pa-fw01",
        "src_ip": "10.1.4.23",
        "dest_ip": "203.0.113.9",
        "index": "netfw2",
        "_cd": "12:345",
    },
]


def _mock_job(requests_mock, rows):
    requests_mock.post(f"{NAMESPACE}/search/v2/jobs", json={"sid": "sid-1"})
    requests_mock.get(
        f"{NAMESPACE}/search/jobs/sid-1",
        json={"entry": [{"content": {"isDone": True, "resultCount": len(rows)}}]},
    )
    requests_mock.get(
        f"{NAMESPACE}/search/v2/jobs/sid-1/results", json={"results": rows}
    )
    requests_mock.delete(f"{NAMESPACE}/search/jobs/sid-1", json={})


def test_rule_hunt_on_firewall_logs_reports_endpoints(
    connector_factory, helper, requests_mock, hunt_event
):
    # Given two firewall events from two endpoints, in two indexes with the same _cd
    _mock_job(requests_mock, FIREWALL_ROWS)
    connector_factory().process_message(hunt_event)
    _, kwargs = helper.report_hunt_run.call_args
    # Then each endpoint is a victim, and the two events stay two hits
    assert sorted(o["host"] for o in kwargs["observations"]) == [
        "10.1.4.22",
        "10.1.4.23",
    ]
    assert len(kwargs["hit_keys"]) == 2
    # And the added fields are never sampled as evidence
    assert all(
        not item["field"].startswith("octi_") for item in kwargs["evidence_sample"]
    )


def test_raw_mode_keeps_the_previous_behavior(
    connector_factory, helper, requests_mock, hunt_event
):
    _mock_job(requests_mock, FIREWALL_ROWS)
    connector_factory({"splunk_hunt": {"host_attribution": "raw"}}).process_message(
        hunt_event
    )
    _, kwargs = helper.report_hunt_run.call_args
    # The appliance is reported, and the two events collapse into one hit key
    assert [o["host"] for o in kwargs["observations"]] == ["pa-fw01"]
    assert len(kwargs["hit_keys"]) == 1
