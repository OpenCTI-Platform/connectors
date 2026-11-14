from typing import Any
from unittest.mock import MagicMock, call

import pytest
from abusech_fplist_connector import ConnectorAbusechFplist, ConnectorSettings
from pycti import OpenCTIConnectorHelper


def _make_settings(dry_run: bool = False) -> ConnectorSettings:
    class StubConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "name": "Test Connector",
                        "scope": "indicator",
                        "log_level": "error",
                        "duration_period": "P1D",
                    },
                    "abusech_fplist": {"api_key": "test-api-key", "dry_run": dry_run},
                }
            )

    return StubConnectorSettings()


def _page(entities: list[dict], has_next: bool = False, cursor: str | None = None):
    return {
        "entities": entities,
        "pagination": {"hasNextPage": has_next, "endCursor": cursor},
    }


def _make_connector(dry_run: bool = False) -> ConnectorAbusechFplist:
    settings = _make_settings(dry_run=dry_run)
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    helper.get_state = MagicMock(return_value={})
    helper.set_state = MagicMock()
    helper.api.work.initiate_work = MagicMock(return_value="work-1")
    helper.api.work.to_processed = MagicMock()
    helper.api.indicator.list = MagicMock(return_value=_page([]))
    helper.api.stix_domain_object.delete = MagicMock()

    connector = ConnectorAbusechFplist(config=settings, helper=helper)
    connector.client = MagicMock()
    return connector


def _patterns_searched(connector: ConnectorAbusechFplist) -> list[str]:
    """Extract the STIX patterns passed to helper.api.indicator.list calls."""
    return [
        c.kwargs["filters"]["filters"][0]["values"][0]
        for c in connector.helper.api.indicator.list.call_args_list
    ]


def test_find_indicators_builds_expected_pattern(mock_opencti_connector_helper):
    connector = _make_connector()
    connector.helper.api.indicator.list.return_value = _page([{"id": "ind-1"}])

    ids = connector._find_indicators("sha256_hash", "a" * 64)

    assert ids == ["ind-1"]
    assert _patterns_searched(connector) == [f"[file:hashes.'SHA-256' = '{'a' * 64}']"]


def test_find_indicators_escapes_backslashes_and_single_quotes(
    mock_opencti_connector_helper,
):
    connector = _make_connector()

    connector._find_indicators("url", "http://evil.example/a'b\\c")

    assert _patterns_searched(connector) == [
        "[url:value = 'http://evil.example/a\\'b\\\\c']"
    ]


def test_find_indicators_ip_port_tries_both_pattern_styles(
    mock_opencti_connector_helper,
):
    connector = _make_connector()
    connector.helper.api.indicator.list.side_effect = [
        _page([{"id": "ind-network-traffic"}]),
        _page([{"id": "ind-ipv4"}]),
    ]

    ids = connector._find_indicators("ip:port", "1.2.3.4:8080")

    assert ids == ["ind-network-traffic", "ind-ipv4"]
    assert _patterns_searched(connector) == [
        "[network-traffic:dst_ref.type = 'ipv4-addr' "
        "AND network-traffic:dst_ref.value = '1.2.3.4' "
        "AND network-traffic:dst_port = 8080]",
        "[ipv4-addr:value = '1.2.3.4']",
    ]


@pytest.mark.parametrize(
    "entry_value",
    [
        pytest.param("1.2.3.4", id="missing_port"),
        pytest.param("1.2.3.4:http", id="non_numeric_port"),
        pytest.param(":8080", id="missing_ip"),
        pytest.param("1.2.3.4:99999", id="port_out_of_range"),
        pytest.param("2001:db8::1:8080", id="ipv6_address"),
        pytest.param("evil.example:443", id="hostname_instead_of_ip"),
    ],
)
def test_find_indicators_invalid_or_unsupported_ip_port_is_skipped(
    mock_opencti_connector_helper, entry_value
):
    connector = _make_connector()

    ids = connector._find_indicators("ip:port", entry_value)

    assert ids == []
    connector.helper.api.indicator.list.assert_not_called()


def test_find_indicators_ip_port_normalizes_leading_zero_port(
    mock_opencti_connector_helper,
):
    connector = _make_connector()

    connector._find_indicators("ip:port", "1.2.3.4:00443")

    assert _patterns_searched(connector) == [
        "[network-traffic:dst_ref.type = 'ipv4-addr' "
        "AND network-traffic:dst_ref.value = '1.2.3.4' "
        "AND network-traffic:dst_port = 443]",
        "[ipv4-addr:value = '1.2.3.4']",
    ]


def test_find_indicators_sha1_tries_both_pattern_styles(
    mock_opencti_connector_helper,
):
    connector = _make_connector()

    connector._find_indicators("sha1_hash", "b" * 40)

    assert _patterns_searched(connector) == [
        f"[file:hashes.'SHA-1' = '{'b' * 40}']",
        f"[file:hashes.SHA1 = '{'b' * 40}']",
    ]


def test_find_indicators_paginates_through_all_pages(mock_opencti_connector_helper):
    connector = _make_connector()
    connector.helper.api.indicator.list.side_effect = [
        _page([{"id": "ind-1"}], has_next=True, cursor="cursor-1"),
        _page([{"id": "ind-2"}]),
    ]

    ids = connector._find_indicators("url", "http://evil.example")

    assert ids == ["ind-1", "ind-2"]
    calls = connector.helper.api.indicator.list.call_args_list
    assert calls[0].kwargs["after"] is None
    assert calls[1].kwargs["after"] == "cursor-1"
    assert all(c.kwargs["withPagination"] is True for c in calls)


def test_find_indicators_collects_all_matches_and_deduplicates(
    mock_opencti_connector_helper,
):
    connector = _make_connector()
    connector.helper.api.indicator.list.side_effect = [
        _page([{"id": "ind-1"}, {"id": "ind-2"}]),
        _page([{"id": "ind-2"}, {"id": "ind-3"}]),
    ]

    ids = connector._find_indicators("ip:port", "1.2.3.4:8080")

    assert ids == ["ind-1", "ind-2", "ind-3"]


def test_find_indicators_unknown_type_returns_empty(mock_opencti_connector_helper):
    connector = _make_connector()

    ids = connector._find_indicators("unknown_type", "some-value")

    assert ids == []
    connector.helper.api.indicator.list.assert_not_called()


def test_remove_entry_deletes_every_matching_indicator(
    mock_opencti_connector_helper,
):
    connector = _make_connector()
    connector.helper.api.indicator.list.side_effect = [
        _page([{"id": "ind-1"}]),
        _page([{"id": "ind-2"}]),
    ]

    connector._remove_entry(
        {"removal_id": "1", "entry_type": "ip:port", "entry_value": "1.2.3.4:8080"}
    )

    assert connector.helper.api.stix_domain_object.delete.call_args_list == [
        call(id="ind-1"),
        call(id="ind-2"),
    ]


def test_remove_entry_dry_run_does_not_delete(mock_opencti_connector_helper):
    connector = _make_connector(dry_run=True)
    connector.helper.api.indicator.list.return_value = _page([{"id": "ind-1"}])

    connector._remove_entry(
        {"removal_id": "1", "entry_type": "url", "entry_value": "http://evil.example"}
    )

    connector.helper.api.stix_domain_object.delete.assert_not_called()


def test_remove_entry_skips_empty_value(mock_opencti_connector_helper):
    connector = _make_connector()

    connector._remove_entry({"removal_id": "1", "entry_type": "url", "entry_value": ""})

    connector.helper.api.indicator.list.assert_not_called()
    connector.helper.api.stix_domain_object.delete.assert_not_called()


def test_process_message_advances_state_to_max_removal_id(
    mock_opencti_connector_helper,
):
    connector = _make_connector()
    connector.helper.get_state.return_value = {"last_removal_id": 100}
    connector.client.get_fplist.return_value = [
        {"removal_id": "102", "entry_type": "url", "entry_value": "http://b.example"},
        {"removal_id": "100", "entry_type": "url", "entry_value": "http://old.example"},
        {"removal_id": "101", "entry_type": "url", "entry_value": "http://a.example"},
    ]
    connector.helper.api.indicator.list.return_value = _page([{"id": "ind-1"}])

    connector.process_message()

    # Entries with removal_id <= 100 are skipped, the others are processed oldest first
    assert _patterns_searched(connector) == [
        "[url:value = 'http://a.example']",
        "[url:value = 'http://b.example']",
    ]
    connector.helper.api.work.initiate_work.assert_called_once()
    connector.helper.api.work.to_processed.assert_called_once()
    state = connector.helper.set_state.call_args.args[0]
    assert state["last_removal_id"] == 102


def test_process_message_without_new_entries_does_not_create_work(
    mock_opencti_connector_helper,
):
    connector = _make_connector()
    connector.helper.get_state.return_value = {"last_removal_id": 100}
    connector.client.get_fplist.return_value = [
        {"removal_id": "99", "entry_type": "url", "entry_value": "http://old.example"},
    ]

    connector.process_message()

    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.set_state.assert_not_called()


def test_process_message_resets_invalid_state_marker(
    mock_opencti_connector_helper,
):
    connector = _make_connector()
    connector.helper.get_state.return_value = {"last_removal_id": "corrupted"}
    connector.client.get_fplist.return_value = [
        {"removal_id": "101", "entry_type": "url", "entry_value": "http://a.example"},
    ]

    connector.process_message()

    state = connector.helper.set_state.call_args.args[0]
    assert state["last_removal_id"] == 101


def test_process_message_dry_run_does_not_advance_state(
    mock_opencti_connector_helper,
):
    connector = _make_connector(dry_run=True)
    connector.helper.get_state.return_value = {"last_removal_id": 100}
    connector.client.get_fplist.return_value = [
        {"removal_id": "101", "entry_type": "url", "entry_value": "http://a.example"},
    ]
    connector.helper.api.indicator.list.return_value = _page([{"id": "ind-1"}])

    connector.process_message()

    connector.helper.api.stix_domain_object.delete.assert_not_called()
    connector.helper.set_state.assert_not_called()
    connector.helper.api.work.to_processed.assert_called_once()


def test_process_message_search_error_aborts_run_and_keeps_state(
    mock_opencti_connector_helper,
):
    connector = _make_connector()
    connector.helper.get_state.return_value = {"last_removal_id": 100}
    connector.client.get_fplist.return_value = [
        {"removal_id": "101", "entry_type": "url", "entry_value": "http://a.example"},
    ]
    connector.helper.api.indicator.list.side_effect = Exception("OpenCTI unavailable")

    connector.process_message()

    connector.helper.set_state.assert_not_called()
    connector.helper.api.work.to_processed.assert_called_once()
    assert connector.helper.api.work.to_processed.call_args.kwargs["in_error"] is True
