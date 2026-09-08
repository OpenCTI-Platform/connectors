from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flare_client.api_client import FlareClient
from pydantic import SecretStr


def _make_client(
    identifier_group_id: int | None = None,
) -> tuple[FlareClient, MagicMock, MagicMock]:
    helper = MagicMock()
    mock_api = MagicMock()
    with patch("flare_client.api_client.FlareApiClient", return_value=mock_api):
        client = FlareClient(
            helper=helper,
            api_key=SecretStr("test-key"),
            api_domain="api.test.io",
            tenant_id=None,
            identifier_group_id=identifier_group_id,
        )
    return client, helper, mock_api


def _make_scroll_page(uids: list[str], next_cursor: str | None = None) -> MagicMock:
    response = MagicMock()
    items = [
        {
            "metadata": {"uid": uid, "severity": "high", "matched_at": "2025-01-02"},
            "tenant_metadata": {"tid": 1},
        }
        for uid in uids
    ]
    response.json.return_value = {"items": items, "next": next_cursor}
    return response


def _make_detail_response(
    uid: str,
    ignored_at: str | None = None,
    remediated_at: str | None = None,
    _tenant_metadata: dict[str, Any] | None = None,
) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "activity": {
            "uid": uid,
            "header": {
                "ignored_at": ignored_at,
                "remediated_at": remediated_at,
            },
        }
    }
    return response


@pytest.fixture(autouse=True)
def no_sleep() -> Any:
    with patch("flare_client.api_client.time.sleep"):
        yield


FROM_DATE = datetime(2025, 1, 1, tzinfo=timezone.utc)
EVENT_TYPES = ["stealer_log"]


class TestFlareClientGetEvents:
    def test_yields_event_with_tenant_metadata(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.return_value = _make_detail_response("uid-1")

        events = list(
            client.get_events(FROM_DATE, event_types=EVENT_TYPES, event_actions=None)
        )

        assert len(events) == 1
        assert events[0]["uid"] == "uid-1"
        assert events[0]["tenant_metadata"] == {"tid": 1}

    def test_yields_event_with_search_item_metadata(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.return_value = _make_detail_response("uid-1")

        events = list(
            client.get_events(FROM_DATE, event_types=EVENT_TYPES, event_actions=None)
        )

        # Severity and matched_at exist only on the search item, not the activity detail.
        assert events[0]["metadata"]["severity"] == "high"
        assert events[0]["metadata"]["matched_at"] == "2025-01-02"

    def test_no_action_filter_yields_all(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.return_value = _make_detail_response("uid-1")

        events = list(
            client.get_events(FROM_DATE, event_types=EVENT_TYPES, event_actions=None)
        )
        assert len(events) == 1

    def test_ignored_filter_skips_non_ignored(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.return_value = _make_detail_response("uid-1", ignored_at=None)

        events = list(
            client.get_events(
                FROM_DATE, event_types=EVENT_TYPES, event_actions=["ignored"]
            )
        )
        assert not events

    def test_ignored_filter_yields_ignored_event(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.return_value = _make_detail_response(
            "uid-1", ignored_at="2025-01-01T00:00:00Z"
        )

        events = list(
            client.get_events(
                FROM_DATE, event_types=EVENT_TYPES, event_actions=["ignored"]
            )
        )
        assert len(events) == 1

    def test_remediated_filter_skips_non_remediated(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.return_value = _make_detail_response("uid-1", remediated_at=None)

        events = list(
            client.get_events(
                FROM_DATE, event_types=EVENT_TYPES, event_actions=["remediated"]
            )
        )
        assert not events

    def test_remediated_filter_yields_remediated_event(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.return_value = _make_detail_response(
            "uid-1", remediated_at="2025-01-02T00:00:00Z"
        )

        events = list(
            client.get_events(
                FROM_DATE, event_types=EVENT_TYPES, event_actions=["remediated"]
            )
        )
        assert len(events) == 1

    def test_unknown_action_logs_and_yields(self) -> None:
        client, helper, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.return_value = _make_detail_response("uid-1")

        events = list(
            client.get_events(
                FROM_DATE, event_types=EVENT_TYPES, event_actions=["unknown"]
            )
        )

        assert len(events) == 1
        helper.connector_logger.info.assert_called()

    def test_severities_sent_as_list_in_search_filters(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page([])]

        list(
            client.get_events(
                FROM_DATE,
                event_types=EVENT_TYPES,
                event_actions=None,
                severities=["high"],
            )
        )

        filters = mock_api.scroll.call_args.kwargs["json"]["filters"]
        # A bare string would make the API match "high or higher" instead of exactly "high".
        assert filters["severity"] == ["high"]

    def test_no_severity_filter_when_unset(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page([])]

        list(
            client.get_events(
                FROM_DATE, event_types=EVENT_TYPES, event_actions=None, severities=[]
            )
        )

        assert "severity" not in mock_api.scroll.call_args.kwargs["json"]["filters"]

    def test_searches_tenant_feed_by_default(self) -> None:
        client, _, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page([])]

        list(client.get_events(FROM_DATE, event_types=EVENT_TYPES, event_actions=None))

        assert (
            mock_api.scroll.call_args.kwargs["url"]
            == "/firework/v4/events/tenant/_search"
        )

    def test_searches_identifier_group_feed_when_configured(self) -> None:
        client, _, mock_api = _make_client(identifier_group_id=42)
        mock_api.scroll.return_value = [_make_scroll_page([])]

        list(
            client.get_events(
                FROM_DATE,
                event_types=EVENT_TYPES,
                event_actions=None,
                severities=["high"],
            )
        )

        kwargs = mock_api.scroll.call_args.kwargs
        assert kwargs["url"] == "/firework/v4/events/identifier_groups/42/_search"
        # Same payload as the tenant feed — only the endpoint changes.
        assert kwargs["json"]["filters"]["severity"] == ["high"]
        assert kwargs["json"]["filters"]["type"] == EVENT_TYPES

    def test_detail_fetch_retries_on_failure_then_succeeds(self) -> None:
        client, helper, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        good_response = _make_detail_response("uid-1")
        mock_api.get.side_effect = [
            RuntimeError("timeout"),
            RuntimeError("timeout"),
            good_response,
        ]

        events = list(
            client.get_events(FROM_DATE, event_types=EVENT_TYPES, event_actions=None)
        )

        assert len(events) == 1
        assert mock_api.get.call_count == 3
        assert helper.connector_logger.error.call_count == 2

    def test_detail_fetch_exhausts_retries_skips_event(self) -> None:
        client, helper, mock_api = _make_client()
        mock_api.scroll.return_value = [_make_scroll_page(["uid-1"])]
        mock_api.get.side_effect = RuntimeError("always fails")

        events = list(
            client.get_events(FROM_DATE, event_types=EVENT_TYPES, event_actions=None)
        )

        assert not events
        assert mock_api.get.call_count == 3
        assert helper.connector_logger.error.call_count == 3
