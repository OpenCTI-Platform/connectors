"""Tests for ZeroFox Alerts API client."""

from unittest.mock import MagicMock, patch

import pytest
from zerofox_alerts.client_api import ZerofoxAlertsClient


@pytest.fixture
def client():
    """Create a client with mocked session."""
    with patch.object(ZerofoxAlertsClient, "__init__", lambda self, *a, **kw: None):
        c = ZerofoxAlertsClient.__new__(ZerofoxAlertsClient)
        c._base_url = "https://api.zerofox.com"
        c._api_token = "test-token"
        c._BaseClientApi__session = MagicMock()
        c._timeout = 60
        return c


class TestSessionHeaders:
    """Tests for authentication headers."""

    def test_headers_include_token(self, client):
        headers = client.session_headers
        assert headers["Authorization"] == "Token test-token"
        assert headers["zf-source"] == "OpenCTI"


class TestPaginateCursor:
    """Tests for the generic cursor pagination helper."""

    def test_single_page(self, client):
        client._get = MagicMock(
            return_value={"alerts": [{"id": 1}, {"id": 2}], "next": None}
        )
        pages = list(client._paginate_cursor("/path", results_key="alerts"))
        assert len(pages) == 1
        assert pages[0] == [{"id": 1}, {"id": 2}]
        client._get.assert_called_once_with("/path", params=None)

    def test_multiple_pages(self, client):
        client._get = MagicMock(
            side_effect=[
                {
                    "alerts": [{"id": 1}],
                    "next": "https://api.zerofox.com/1.0/alerts/?cursor=abc",
                },
                {"alerts": [{"id": 2}], "next": None},
            ]
        )
        pages = list(
            client._paginate_cursor(
                "/1.0/alerts/", params={"limit": 10}, results_key="alerts"
            )
        )
        assert len(pages) == 2
        assert pages[0] == [{"id": 1}]
        assert pages[1] == [{"id": 2}]
        # First call with params, second with stripped URL
        assert client._get.call_count == 2

    def test_stops_on_empty_results(self, client):
        client._get = MagicMock(
            side_effect=[
                {
                    "alerts": [{"id": 1}],
                    "next": "https://api.zerofox.com/1.0/alerts/?cursor=abc",
                },
                {
                    "alerts": [],
                    "next": "https://api.zerofox.com/1.0/alerts/?cursor=def",
                },
            ]
        )
        pages = list(client._paginate_cursor("/path", results_key="alerts"))
        assert len(pages) == 1

    def test_params_cleared_after_first_request(self, client):
        """After the first request, params should not be reused."""
        client._get = MagicMock(
            side_effect=[
                {
                    "alerts": [{"id": 1}],
                    "next": "https://api.zerofox.com/1.0/alerts/?cursor=abc",
                },
                {"alerts": [{"id": 2}], "next": None},
            ]
        )
        list(
            client._paginate_cursor(
                "/1.0/alerts/", params={"limit": 50}, results_key="alerts"
            )
        )
        # Second call uses the cursor URL, no params
        second_call = client._get.call_args_list[1]
        assert second_call[0][0] == "/1.0/alerts/?cursor=abc"


class TestGetAlerts:
    """Tests for the get_alerts method."""

    def test_builds_params_correctly(self, client):
        client._paginate_cursor = MagicMock(return_value=iter([]))
        list(
            client.get_alerts(
                min_timestamp="2025-01-01T00:00:00Z",
                status=["open", "escalated"],
                page_size=50,
            )
        )
        call_kwargs = client._paginate_cursor.call_args[1]
        params = call_kwargs["params"]
        assert params["min_timestamp"] == "2025-01-01T00:00:00Z"
        assert params["status"] == "open,escalated"
        assert params["limit"] == 50
        assert params["sort_field"] == "timestamp"
        assert params["sort_direction"] == "asc"

    def test_omits_optional_params_when_none(self, client):
        client._paginate_cursor = MagicMock(return_value=iter([]))
        list(client.get_alerts())
        call_kwargs = client._paginate_cursor.call_args[1]
        params = call_kwargs["params"]
        assert "min_timestamp" not in params
        assert "status" not in params

    def test_delegates_to_paginate_cursor(self, client):
        client._paginate_cursor = MagicMock(
            return_value=iter([[{"id": 1}], [{"id": 2}]])
        )
        pages = list(client.get_alerts(min_timestamp="2025-01-01T00:00:00Z"))
        assert len(pages) == 2
        client._paginate_cursor.assert_called_once()
        call_kwargs = client._paginate_cursor.call_args[1]
        assert call_kwargs["results_key"] == "alerts"
        assert call_kwargs["next_key"] == "next"


class TestGetAlertById:
    """Tests for get_alert_by_id."""

    def test_calls_correct_endpoint(self, client):
        client._get = MagicMock(return_value={"id": 123, "status": "open"})
        result = client.get_alert_by_id(123)
        client._get.assert_called_once_with("/1.0/alerts/123/")
        assert result["id"] == 123
