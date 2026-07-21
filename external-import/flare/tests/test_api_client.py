from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from flare_client.api_client import FlareClient

_FROM_DATE = datetime(2025, 1, 1, tzinfo=timezone.utc)
_ITEM = {"metadata": {"uid": "uid-1"}, "tenant_metadata": {}}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda _: None)


@pytest.fixture
def mock_helper() -> MagicMock:
    return MagicMock()


@pytest.fixture
def mock_api() -> MagicMock:
    return MagicMock()


@pytest.fixture
def client(mock_helper: MagicMock, mock_api: MagicMock) -> FlareClient:
    c = FlareClient.__new__(FlareClient)
    c.helper = mock_helper
    c._api = mock_api
    return c


def _scroll_response(items: list, next_cursor: str | None = None) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {"items": items, "next": next_cursor}
    return response


def _event_response(header: dict | None = None) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {"activity": {"header": header or {}}}
    return response


class TestGetEvents:
    def test_filters_include_event_types(
        self, client: FlareClient, mock_api: MagicMock
    ) -> None:
        mock_api.scroll.return_value = iter([_scroll_response([_ITEM])])
        mock_api.get.return_value = _event_response()

        list(
            client.get_events(
                _FROM_DATE, event_types=["stealer_log", "domain"], event_actions=None
            )
        )

        filters = mock_api.scroll.call_args.kwargs["json"]["filters"]
        assert filters["type"] == ["stealer_log", "domain"]

    @pytest.mark.parametrize(
        "event_actions, event_header, expected_count, expected_log",
        [
            pytest.param(None, None, 1, None, id="none_event_actions"),
            pytest.param([], None, 1, None, id="empty_event_actions"),
            pytest.param(
                ["ignored", "remediated"],
                None,
                0,
                ("debug", "Skipping event — not ignored"),
                id="filled_event_actions",
            ),
            pytest.param(
                ["unknown"],
                None,
                1,
                (
                    "info",
                    "Unsupported event actions configured — only 'ignored' and 'remediated' are supported",
                ),
                id="unknown_event_actions",
            ),
            pytest.param(
                ["ignored"],
                None,
                0,
                ("debug", "Skipping event — not ignored"),
                id="ignored_filter_skips_non_ignored",
            ),
            pytest.param(
                ["ignored"],
                {"ignored_at": "2025-01-01T00:00:00Z"},
                1,
                None,
                id="ignored_filter_yields_ignored_event",
            ),
            pytest.param(
                ["remediated"],
                None,
                0,
                ("debug", "Skipping event — not remediated"),
                id="remediated_filter_skips_non_remediated",
            ),
            pytest.param(
                ["remediated"],
                {"remediated_at": "2025-01-01T00:00:00Z"},
                1,
                None,
                id="remediated_filter_yields_remediated_event",
            ),
        ],
    )
    def test_event_actions(
        self,
        event_actions: list[str] | None,
        event_header: dict | None,
        expected_count: int,
        expected_log: tuple[str, str] | None,
        client: FlareClient,
        mock_api: MagicMock,
        mock_helper: MagicMock,
    ) -> None:
        mock_api.scroll.return_value = iter([_scroll_response([_ITEM])])
        mock_api.get.return_value = _event_response(header=event_header)

        result = list(
            client.get_events(_FROM_DATE, event_types=[], event_actions=event_actions)
        )

        assert len(result) == expected_count
        if expected_log is not None:
            method, message = expected_log
            calls = getattr(mock_helper.connector_logger, method).call_args_list
            assert any(message in call.args[0] for call in calls)
        else:
            debug_msgs = [
                c.args[0] for c in mock_helper.connector_logger.debug.call_args_list
            ]
            assert not any("Skipping" in msg for msg in debug_msgs)
            info_msgs = [
                c.args[0] for c in mock_helper.connector_logger.info.call_args_list
            ]
            assert not any("Unsupported" in msg for msg in info_msgs)

    def test_captures_http_request_errors(
        self, client: FlareClient, mock_helper: MagicMock, mock_api: MagicMock
    ) -> None:
        mock_api.scroll.return_value = iter([_scroll_response([_ITEM])])
        mock_api.get.side_effect = Exception("connection error")

        result = list(client.get_events(_FROM_DATE, event_types=[], event_actions=None))

        assert result == []
        assert mock_helper.connector_logger.error.call_count == 3
        error_msgs = [
            c.args[0] for c in mock_helper.connector_logger.error.call_args_list
        ]
        assert all("Failed to fetch event" in msg for msg in error_msgs)
