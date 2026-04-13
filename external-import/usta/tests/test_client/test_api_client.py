"""Unit tests for the USTA API client — 100 % coverage."""

# pylint: disable=missing-function-docstring,missing-class-docstring,redefined-outer-name,protected-access

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from usta_client.api_client import UstaClient, UstaClientError


@pytest.fixture
def client(mock_helper):
    """Create an UstaClient with mocked session and rate limiter."""
    with patch("usta_client.api_client.Limiter"):
        c = UstaClient(
            helper=mock_helper,
            base_url="https://usta.prodaft.com",
            api_key="test-key",
            page_size=10,
        )
    c.session = MagicMock()
    c.rate_limiter = MagicMock()
    c.rate_limiter.__enter__ = MagicMock(return_value=None)
    c.rate_limiter.__exit__ = MagicMock(return_value=False)
    return c


# =====================================================================
# _request
# =====================================================================


class TestRequest:
    def test_success_absolute_url(self, client):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"results": []}
        client.session.get.return_value = resp
        result = client._request("https://other.com/api", params={"a": 1})
        assert result == {"results": []}
        client.session.get.assert_called_once_with(
            "https://other.com/api", params={"a": 1}, timeout=60
        )

    def test_success_relative_url(self, client):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"ok": True}
        client.session.get.return_value = resp
        result = client._request("/api/test")
        assert result == {"ok": True}
        call_url = client.session.get.call_args[0][0]
        assert call_url == "https://usta.prodaft.com/api/test"

    def test_401_raises_client_error(self, client):
        resp = MagicMock()
        resp.status_code = 401
        client.session.get.return_value = resp
        with pytest.raises(UstaClientError, match="Authentication failed"):
            client._request("/api/test")

    def test_403_raises_client_error(self, client):
        resp = MagicMock()
        resp.status_code = 403
        client.session.get.return_value = resp
        with pytest.raises(UstaClientError, match="Access denied"):
            client._request("/api/test")


# =====================================================================
# Cursor-based pagination
# =====================================================================


class TestCursorPagination:
    def test_single_page(self, client):
        client._request = MagicMock(
            return_value={"results": [{"id": 1}], "next": None, "cursor": "c1"}
        )
        pages = list(client._fetch_cursor_paginated("/ep", start="2026-01-01"))
        assert pages == [[{"id": 1}]]
        assert client._request.call_count == 1

    def test_multi_page(self, client):
        client._request = MagicMock(
            side_effect=[
                {"results": [{"id": 1}], "next": "https://next", "cursor": "c1"},
                {"results": [{"id": 2}], "next": None, "cursor": "c2"},
            ]
        )
        pages = list(client._fetch_cursor_paginated("/ep", start="2026-01-01"))
        assert len(pages) == 2

    def test_empty_results(self, client):
        client._request = MagicMock(return_value={"results": [], "next": None})
        pages = list(client._fetch_cursor_paginated("/ep", start="2026-01-01"))
        assert not pages

    def test_next_url_used_on_second_page(self, client):
        client._request = MagicMock(
            side_effect=[
                {"results": [{"id": 1}], "next": "https://page2"},
                {"results": [], "next": None},
            ]
        )
        list(client._fetch_cursor_paginated("/ep", start="s"))
        # Second call should use the next URL without params
        second_call = client._request.call_args_list[1]
        assert second_call[0][0] == "https://page2"


# =====================================================================
# Page-based pagination
# =====================================================================


class TestPagePagination:
    def test_single_page(self, client):
        client._request = MagicMock(
            return_value={"count": 1, "results": [{"id": 1}], "next": None}
        )
        pages = list(client._fetch_page_paginated("/ep", start="s"))
        assert pages == [[{"id": 1}]]

    def test_multi_page(self, client):
        client._request = MagicMock(
            side_effect=[
                {"count": 2, "results": [{"id": 1}], "next": "https://p2"},
                {"count": 2, "results": [{"id": 2}], "next": None},
            ]
        )
        pages = list(client._fetch_page_paginated("/ep", start="s"))
        assert len(pages) == 2

    def test_empty(self, client):
        client._request = MagicMock(
            return_value={"count": 0, "results": [], "next": None}
        )
        assert not list(client._fetch_page_paginated("/ep"))

    def test_custom_order_param(self, client):
        client._request = MagicMock(return_value={"results": [], "next": None})
        list(client._fetch_page_paginated("/ep", start="s", order_param_name="order"))
        params = client._request.call_args[1]["params"]
        assert "order" in params
        assert "ordering" not in params

    def test_no_start(self, client):
        client._request = MagicMock(return_value={"results": [], "next": None})
        list(client._fetch_page_paginated("/ep"))
        params = client._request.call_args[1]["params"]
        assert "start" not in params


# =====================================================================
# Public methods (thin wrappers)
# =====================================================================


class TestPublicMethods:
    def _mock_pagination(self, client, method_name):
        """Patch the underlying paginator to return one page."""
        results = [[{"id": 1}]]
        if "cursor" in method_name or method_name in (
            "get_malicious_urls",
            "get_malware_hashes",
        ):
            client._fetch_cursor_paginated = MagicMock(return_value=iter(results))
        else:
            client._fetch_page_paginated = MagicMock(return_value=iter(results))

    def test_get_malicious_urls(self, client):
        client._fetch_cursor_paginated = MagicMock(return_value=iter([[{"id": 1}]]))
        pages = list(client.get_malicious_urls("2026-01-01"))
        assert len(pages) == 1

    def test_get_phishing_sites(self, client):
        client._fetch_page_paginated = MagicMock(return_value=iter([[{"id": 1}]]))
        pages = list(client.get_phishing_sites("2026-01-01"))
        assert len(pages) == 1

    def test_get_malware_hashes(self, client):
        client._fetch_cursor_paginated = MagicMock(return_value=iter([[{"id": 1}]]))
        pages = list(client.get_malware_hashes("2026-01-01"))
        assert len(pages) == 1

    def test_get_compromised_credentials(self, client):
        client._fetch_page_paginated = MagicMock(return_value=iter([[{"id": 1}]]))
        pages = list(client.get_compromised_credentials("2026-01-01"))
        assert len(pages) == 1
        # Verify order_param_name="order" is passed
        call_kwargs = client._fetch_page_paginated.call_args[1]
        assert call_kwargs["order_param_name"] == "order"

    def test_get_credit_card_tickets(self, client):
        client._fetch_page_paginated = MagicMock(return_value=iter([[{"id": 1}]]))
        pages = list(client.get_credit_card_tickets("2026-01-01"))
        assert len(pages) == 1

    def test_get_deep_sight_tickets(self, client):
        client._fetch_page_paginated = MagicMock(return_value=iter([[{"id": 1}]]))
        pages = list(client.get_deep_sight_tickets("2026-01-01"))
        assert len(pages) == 1
        # Must use page-based pagination with ordering=created
        call_kwargs = client._fetch_page_paginated.call_args
        assert call_kwargs[0][0] == client.ENDPOINT_DEEP_SIGHT_TICKETS
