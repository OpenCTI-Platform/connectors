"""Orchestration tests for the Enrichment connector (helper + client mocked)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.connector import MetrasEnrichmentConnector
from connectors_sdk.models.enums import TLPLevel
from pydantic import SecretStr

IPV4_ID = "ipv4-addr--11111111-1111-4111-8111-111111111111"
TLP_RED = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"


def _enr(max_tlp=TLPLevel.AMBER_STRICT):
    cfg = SimpleNamespace(
        metras=SimpleNamespace(
            api_base_url="http://x/api",
            api_key=SecretStr("k"),
            verify_ssl=True,
            max_tlp=max_tlp,
        ),
        connector=SimpleNamespace(scope=["IPv4-Addr", "StixFile"]),
    )
    helper = MagicMock()
    helper.connect_confidence_level = 50
    helper.stix2_create_bundle.return_value = "{}"
    helper.send_stix2_bundle.return_value = [1]
    conn = MetrasEnrichmentConnector(cfg, helper)
    conn.client = MagicMock()
    return conn, helper


def test_out_of_scope_returns_message():
    conn, _ = _enr()
    msg = conn.process_message(
        {"stix_entity": {"type": "Domain-Name", "id": "domain-name--x"}}
    )
    assert "not in scope" in msg


def test_file_alias_is_in_scope():
    conn, _ = _enr()
    assert conn.entity_in_scope("file") is True  # file -> stixfile alias


def test_missing_stix_id_aborts():
    conn, _ = _enr()
    with pytest.raises(ValueError):
        conn.process_message({"stix_entity": {"type": "IPv4-Addr", "value": "1.2.3.4"}})


def test_tlp_gate_blocks_above_max():
    conn, _ = _enr(max_tlp=TLPLevel.GREEN)
    msg = conn.process_message(
        {
            "stix_entity": {
                "type": "IPv4-Addr",
                "id": IPV4_ID,
                "value": "1.2.3.4",
                "object_marking_refs": [TLP_RED],
            }
        }
    )
    assert "exceeds max" in msg


def test_ipv4_hit_sends_bundle_with_cleanup_flag():
    conn, helper = _enr()
    conn.client.alerts_by_agent_ip.return_value = {"data": [{"alert_name": "r1"}]}
    conn.client.list_endpoints.return_value = {"endpoints": []}
    msg = conn.process_message(
        {"stix_entity": {"type": "IPv4-Addr", "id": IPV4_ID, "value": "10.0.0.1"}}
    )
    assert "Sent" in msg
    _, kwargs = helper.send_stix2_bundle.call_args
    assert kwargs.get("cleanup_inconsistent_bundle") is True


def test_all_lookups_fail_raises():
    conn, _ = _enr()
    boom = MagicMock(side_effect=Exception("x"))
    conn.client.alerts_by_agent_ip = boom
    conn.client.list_endpoints = boom
    with pytest.raises(ValueError):
        conn.process_message(
            {"stix_entity": {"type": "IPv4-Addr", "id": IPV4_ID, "value": "10.0.0.1"}}
        )
