"""Orchestration tests for the Stream connector (helper + client mocked)."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.connector import MetrasStreamConnector
from pydantic import SecretStr


def _stream():
    cfg = SimpleNamespace(
        metras=SimpleNamespace(
            api_base_url="http://x/api",
            api_key=SecretStr("k"),
            verify_ssl=True,
            blocklist_action="ALERT",
            blocklist_platform="windows",
            blocklist_severity="Medium",
        )
    )
    helper = MagicMock()
    conn = MetrasStreamConnector(cfg, helper)
    conn.client = MagicMock()
    return conn, helper


def _msg(event, data):
    return SimpleNamespace(event=event, data=json.dumps({"data": data}))


def test_file_indicator_creates_blocklist():
    conn, _ = _stream()
    conn.client.list_blocklists.return_value = {"data": []}
    conn._process_event(
        _msg(
            "create",
            {
                "type": "indicator",
                "name": "evil",
                "pattern": "[file:name = 'evil.exe']",
            },
        )
    )
    assert conn.client.create_blocklist.called
    item = conn.client.create_blocklist.call_args[0][0][0]
    assert item["file_paths"] == ["evil.exe"] and item["name"] == "opencti-evil"


def test_non_file_indicator_skipped():
    conn, _ = _stream()
    conn._process_event(
        _msg(
            "create",
            {
                "type": "indicator",
                "name": "ip",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
            },
        )
    )
    assert not conn.client.create_blocklist.called


def test_existing_blocklist_is_updated_not_created():
    conn, _ = _stream()
    conn.client.list_blocklists.return_value = {
        "data": [{"id": "b1", "name": "opencti-evil"}]
    }
    conn._process_event(
        _msg(
            "update",
            {
                "type": "indicator",
                "name": "evil",
                "pattern": "[file:name = 'evil.exe']",
            },
        )
    )
    assert conn.client.update_blocklist.called
    assert not conn.client.create_blocklist.called


def test_delete_resolves_and_deletes():
    conn, _ = _stream()
    conn.client.list_blocklists.return_value = {
        "data": [{"id": "b1", "name": "opencti-evil"}]
    }
    conn._process_event(
        _msg(
            "delete",
            {
                "type": "indicator",
                "name": "evil",
                "pattern": "[file:name = 'evil.exe']",
            },
        )
    )
    conn.client.delete_blocklist.assert_called_once_with("b1")


def test_non_indicator_ignored():
    conn, _ = _stream()
    conn._process_event(_msg("create", {"type": "malware", "name": "x"}))
    assert not conn.client.create_blocklist.called


def test_push_failure_does_not_raise():
    conn, _ = _stream()
    conn.client.list_blocklists.return_value = {"data": []}
    conn.client.create_blocklist.side_effect = Exception("boom")
    # Must not raise — stream connectors log and continue.
    conn._process_event(
        _msg(
            "create",
            {
                "type": "indicator",
                "name": "evil",
                "pattern": "[file:name = 'evil.exe']",
            },
        )
    )
