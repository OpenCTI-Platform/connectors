import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cloudflare_rules_list.client import CloudflareAPIError
from cloudflare_rules_list.connector import Connector, _parse_interval


# --------------------------------------------------------------------------- #
# _parse_interval
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value, expected",
    [
        ("1h", 3600),
        ("30m", 1800),
        ("1h30m", 5400),
        ("45s", 45),
        ("90", 90),
        ("", 3600),
        ("garbage", 3600),
        ("0", 3600),
        (None, 3600),
    ],
)
def test_parse_interval(value, expected):
    assert _parse_interval(value) == expected


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def helper():
    h = MagicMock()
    h.connector_logger = MagicMock()
    return h


@pytest.fixture
def client():
    return MagicMock()


@pytest.fixture
def config():
    return SimpleNamespace(
        cloudflare=SimpleNamespace(list_id="list-123"),
        connector=SimpleNamespace(sync_interval="1h"),
    )


@pytest.fixture
def connector(helper, config, client):
    conn = Connector(helper=helper, config=config, client=client)
    # Force sync to trigger on demand in tests.
    conn.sync_interval = 0
    return conn


# --------------------------------------------------------------------------- #
# _extract_ipv4
# --------------------------------------------------------------------------- #
def test_extract_ipv4_from_indicator_pattern(connector):
    data = {"type": "indicator", "pattern": "[ipv4-addr:value = '192.0.2.1']"}
    assert connector._extract_ipv4(data) == "192.0.2.1"


def test_extract_ipv4_from_api_indicator(connector):
    # OpenCTI API (full-sync) shape: entity_type=="Indicator", no lowercase type.
    data = {"entity_type": "Indicator", "pattern": "[ipv4-addr:value = '192.0.2.30']"}
    assert connector._extract_ipv4(data) == "192.0.2.30"


def test_extract_ipv4_from_api_indicator_no_match(connector):
    data = {"entity_type": "Indicator", "pattern": "[domain-name:value = 'evil.com']"}
    assert connector._extract_ipv4(data) is None


def test_extract_ipv4_from_indicator_no_match(connector):
    data = {"type": "indicator", "pattern": "[domain-name:value = 'evil.com']"}
    assert connector._extract_ipv4(data) is None


def test_extract_ipv4_from_indicator_empty_pattern(connector):
    assert connector._extract_ipv4({"type": "indicator"}) is None


def test_extract_ipv4_from_stix_sco(connector):
    data = {"type": "ipv4-addr", "value": "203.0.113.5"}
    assert connector._extract_ipv4(data) == "203.0.113.5"


def test_extract_ipv4_from_opencti_observable(connector):
    data = {"entity_type": "IPv4-Addr", "observable_value": "198.51.100.7"}
    assert connector._extract_ipv4(data) == "198.51.100.7"


def test_extract_ipv4_unrelated_type(connector):
    assert connector._extract_ipv4({"type": "domain-name", "value": "x"}) is None


# --------------------------------------------------------------------------- #
# _object_id
# --------------------------------------------------------------------------- #
def test_object_id_prefers_id(connector):
    assert connector._object_id({"id": "a", "x_opencti_id": "b"}) == "a"


def test_object_id_falls_back_to_x_opencti_id(connector):
    assert connector._object_id({"x_opencti_id": "b"}) == "b"


def test_object_id_none(connector):
    assert connector._object_id({}) is None


# --------------------------------------------------------------------------- #
# process_message routing
# --------------------------------------------------------------------------- #
def _msg(event, payload):
    return SimpleNamespace(event=event, data=json.dumps({"data": payload}))


def test_process_message_create_caches(connector):
    connector.process_message(
        _msg("create", {"id": "ind-1", "type": "ipv4-addr", "value": "1.1.1.1"})
    )
    assert connector._indicator_cache["ind-1"] == "1.1.1.1"


def test_process_message_message_event_treated_as_create(connector):
    connector.process_message(
        _msg("message", {"id": "ind-2", "type": "ipv4-addr", "value": "2.2.2.2"})
    )
    assert connector._indicator_cache["ind-2"] == "2.2.2.2"


def test_process_message_delete_removes(connector):
    connector._indicator_cache["ind-3"] = "3.3.3.3"
    connector.process_message(_msg("delete", {"id": "ind-3", "type": "ipv4-addr"}))
    assert "ind-3" not in connector._indicator_cache


def test_process_message_bad_json_warns(connector):
    connector.process_message(SimpleNamespace(event="create", data="not-json"))
    connector.logger.warning.assert_called_once()


def test_process_message_missing_data_key_warns(connector):
    connector.process_message(SimpleNamespace(event="create", data=json.dumps({})))
    connector.logger.warning.assert_called_once()


def test_process_message_exits_on_keyboard_interrupt(connector, monkeypatch):
    monkeypatch.setattr(
        connector, "_handle_upsert", MagicMock(side_effect=KeyboardInterrupt)
    )
    with pytest.raises(SystemExit):
        connector.process_message(
            _msg("create", {"id": "x", "type": "ipv4-addr", "value": "9.9.9.9"})
        )


def test_process_message_swallows_unexpected_errors(connector, monkeypatch):
    monkeypatch.setattr(
        connector, "_handle_upsert", MagicMock(side_effect=RuntimeError("boom"))
    )
    connector.process_message(
        _msg("create", {"id": "x", "type": "ipv4-addr", "value": "9.9.9.9"})
    )
    connector.logger.error.assert_called_once()


# --------------------------------------------------------------------------- #
# upsert / delete
# --------------------------------------------------------------------------- #
def test_handle_upsert_ignores_without_value(connector):
    connector._handle_upsert({"id": "i", "type": "domain-name"})
    assert connector._indicator_cache == {}


def test_handle_upsert_ignores_without_id(connector):
    connector._handle_upsert({"type": "ipv4-addr", "value": "1.2.3.4"})
    assert connector._indicator_cache == {}


def test_handle_delete_unknown_id_is_noop(connector):
    connector._handle_delete({"id": "unknown"})
    assert connector._indicator_cache == {}


# --------------------------------------------------------------------------- #
# _check_sync / _sync_to_cloudflare
# --------------------------------------------------------------------------- #
def test_check_sync_does_not_sync_before_interval(connector, monkeypatch):
    connector.sync_interval = 9999
    connector._last_sync_time = 0.0
    monkeypatch.setattr("cloudflare_rules_list.connector.time.monotonic", lambda: 1.0)
    sync = MagicMock()
    monkeypatch.setattr(connector, "_sync_to_cloudflare", sync)
    connector._check_sync()
    sync.assert_not_called()


def test_sync_to_cloudflare_empty_cache(connector):
    connector._sync_to_cloudflare()
    connector.client.replace_list_items.assert_not_called()
    connector.logger.info.assert_any_call("No indicators to sync")


def test_sync_to_cloudflare_empty_cache_does_not_open_throttle(connector, monkeypatch):
    # An empty push must NOT stamp _last_sync_time, or the first real indicator
    # could be delayed by up to sync_interval before it is synced.
    monkeypatch.setattr("cloudflare_rules_list.connector.time.monotonic", lambda: 123.0)
    connector._last_sync_time = 0.0
    connector._indicator_cache = {}
    connector._sync_to_cloudflare()
    assert connector._last_sync_time == 0.0


def test_sync_to_cloudflare_with_operation(connector):
    connector._indicator_cache = {"ind-1": "1.1.1.1"}
    connector.client.replace_list_items.return_value = {"operation_id": "op-1"}
    connector.client.wait_for_operation.return_value = {"status": "completed"}

    connector._sync_to_cloudflare()

    connector.client.replace_list_items.assert_called_once_with(
        "list-123", [{"ip": "1.1.1.1", "comment": "OpenCTI: ind-1"}]
    )
    connector.client.wait_for_operation.assert_called_once_with("op-1")


def test_sync_to_cloudflare_without_operation_id(connector):
    connector._indicator_cache = {"ind-1": "1.1.1.1"}
    connector.client.replace_list_items.return_value = {}
    connector._sync_to_cloudflare()
    connector.client.wait_for_operation.assert_not_called()


def test_sync_to_cloudflare_handles_api_error(connector):
    connector._indicator_cache = {"ind-1": "1.1.1.1"}
    connector.client.replace_list_items.side_effect = CloudflareAPIError("nope")
    connector._sync_to_cloudflare()
    connector.logger.error.assert_called_once()


# --------------------------------------------------------------------------- #
# _full_sync
# --------------------------------------------------------------------------- #
def test_full_sync_loads_indicators_and_observables(connector):
    # Use the real OpenCTI API object shape: entity_type (capitalized), no
    # lowercase STIX `type`. This mirrors helper.api.*.list() output so a
    # regression in _extract_ipv4's indicator handling is caught here.
    connector.helper.api.indicator.list.return_value = [
        {
            "id": "ind-1",
            "entity_type": "Indicator",
            "pattern": "[ipv4-addr:value = '1.1.1.1']",
        },
        {
            "id": "ind-2",
            "entity_type": "Indicator",
            "pattern": "[domain-name:value = 'x']",
        },
    ]
    connector.helper.api.stix_cyber_observable.list.return_value = [
        {"id": "obs-1", "entity_type": "IPv4-Addr", "observable_value": "8.8.8.8"},
    ]
    connector.client.replace_list_items.return_value = {}

    connector._full_sync()

    assert connector._indicator_cache == {"ind-1": "1.1.1.1", "obs-1": "8.8.8.8"}
    connector.client.replace_list_items.assert_called_once()


def test_full_sync_handles_observable_error(connector):
    connector.helper.api.indicator.list.return_value = []
    connector.helper.api.stix_cyber_observable.list.side_effect = RuntimeError("boom")
    connector.client.replace_list_items.return_value = {}

    connector._full_sync()

    connector.logger.warning.assert_called_once()


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
def test_run_verifies_list_then_listens(connector, monkeypatch):
    connector.client.get_list.return_value = {"name": "blocklist", "kind": "ip"}
    full_sync = MagicMock()
    monkeypatch.setattr(connector, "_full_sync", full_sync)

    connector.run()

    connector.client.get_list.assert_called_once_with("list-123")
    full_sync.assert_called_once()
    connector.helper.listen_stream.assert_called_once_with(
        message_callback=connector.process_message
    )


def test_run_raises_when_list_missing(connector):
    connector.client.get_list.side_effect = CloudflareAPIError("404")
    with pytest.raises(CloudflareAPIError):
        connector.run()
    connector.helper.listen_stream.assert_not_called()


def test_run_continues_when_full_sync_fails(connector, monkeypatch):
    connector.client.get_list.return_value = {"name": "blocklist", "kind": "ip"}
    monkeypatch.setattr(
        connector, "_full_sync", MagicMock(side_effect=RuntimeError("boom"))
    )
    connector.run()
    connector.helper.listen_stream.assert_called_once()
