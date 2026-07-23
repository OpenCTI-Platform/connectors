"""Converter tests (no connectors-sdk / no live OpenCTI needed)."""

from unittest.mock import MagicMock

from connector.converter_to_stix import ConverterToStix


def _converter():
    helper = MagicMock()
    helper.connect_confidence_level = 50
    return ConverterToStix(helper, tlp_level="amber")


def test_process_alert_creates_incident_and_attack_pattern():
    conv = _converter()
    alert = {
        "id": "1748880_NToxMDc0Ng",
        "alert_name": "test-rule-1",
        "alert_source_name": "behavior",
        "type": "WATCHLIST",
        "severity": "Critical",
        "agent_ip": "10.200.0.214",
        "url": "https://evil.example.com",
        "endpoint_name": "TEST-ENDPOINT",
        "endpoint_id": "1e53d0d4-84e4-4a7b-bff7-d0b216c4ac40",
        "mitre_ids": ["T1059", "T1059.001"],
        "last_occurrence_time": "2025-11-11T11:36:20.162Z",
        "occurrence_count": 1,
        "process": {"name": "WUDFHost.exe", "guid": "{bda3de7f}"},
        "tags": ["abc"],
    }
    objs = conv.process_alert(alert)
    types = [o["type"] for o in objs]
    assert "incident" in types
    assert types.count("attack-pattern") == 2
    assert "url" in types
    # Affected endpoint is a System identity; internal agent_ip is NOT an IPv4-Addr IOC.
    assert "identity" in types
    assert "ipv4-addr" not in types
    assert "relationship" in types


def test_process_binary_malicious_only():
    conv = _converter()
    banned = {
        "md5": "2e9fc997dea8b0fc30761e7d2e2c54be",
        "sha256": "27e38928588e5153becf77dabe6a5e5df8377ab814ef9127f68155ed176e1181",
        "name": "evil.dll",
        "file_size_bytes": 1024,
        "runnability_status": "banned",
        "first_endpoint_name": "TEST-ENDPOINT",
    }
    signed = {
        "md5": "abc",
        "name": "good.dll",
        "signature_status": "Signed",
        "runnability_status": "allowed",
    }
    banned_objs = conv.process_binary(banned, malicious_only=True)
    assert any(o["type"] == "file" for o in banned_objs)
    assert any(
        o["type"] == "identity" for o in banned_objs
    )  # System for first endpoint
    assert conv.process_binary(signed, malicious_only=True) == []
    assert any(
        o["type"] == "file" for o in conv.process_binary(signed, malicious_only=False)
    )


def test_process_endpoint_creates_system_identity():
    conv = _converter()
    endpoint = {
        "id": "4373f3cc-80ec-4f57-bea6-6d431b2d4b8d",
        "name": "win19",
        "os": "windows",
        "serial": "764QDF2",
        "sc_connection_info": {"tunnel_ip": "172.16.68.7"},
        "nw_info": {"interfaces": [{"ips": ["10.0.0.5"]}]},
    }
    objs = conv.process_endpoint(endpoint)
    types = [o["type"] for o in objs]
    # Endpoint is a System identity; internal IPs go in the description, not as IOCs.
    assert types == ["identity"]
    assert "172.16.68.7" in objs[0]["description"]
    assert "10.0.0.5" in objs[0]["description"]


def test_incident_id_stable_across_occurrence_time():
    # A recurring alert (same id, newer last_occurrence_time) must map to the SAME
    # Incident id so OpenCTI updates it instead of creating a duplicate.
    conv = _converter()
    base = {
        "id": "alert-42",
        "alert_name": "recurring-rule",
        "severity": "high",
        "last_occurrence_time": "2025-11-11T11:36:20.162Z",
    }

    def _incident_id(alert):
        return next(
            o["id"] for o in conv.process_alert(alert) if o["type"] == "incident"
        )

    newer = {**base, "last_occurrence_time": "2025-12-01T09:00:00.000Z"}
    assert _incident_id(base) == _incident_id(newer)
    # A different alert id yields a different Incident.
    assert _incident_id({**base, "id": "alert-99"}) != _incident_id(base)
