"""Tests for SublimeClient API client."""

from unittest.mock import Mock, patch

import pytest
from pydantic import HttpUrl, SecretStr
from sublime_client.api_client import SublimeClient


@pytest.fixture
def client(mock_helper):
    """Create a SublimeClient instance with mocked dependencies."""
    return SublimeClient(
        helper=mock_helper,
        base_url=HttpUrl("https://platform.sublime.security"),
        api_key=SecretStr("test-api-key"),
    )


class TestSublimeClientInit:
    """Test client initialization."""

    def test_init_sets_auth_header(self, mock_helper):
        client = SublimeClient(
            helper=mock_helper,
            base_url=HttpUrl("https://platform.sublime.security"),
            api_key=SecretStr("my-secret-token"),
        )
        assert client.session.headers["Authorization"] == "Bearer my-secret-token"
        assert client.session.headers["Accept"] == "application/json"

    def test_init_sets_base_url(self, mock_helper):
        client = SublimeClient(
            helper=mock_helper,
            base_url=HttpUrl("https://custom.api.example.com"),
            api_key=SecretStr("key"),
        )
        assert "custom.api.example.com" in client.base_url.unicode_string()


class TestGetGroupIds:
    """Test get_group_ids method."""

    def test_returns_group_ids(self, client):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "all_group_canonical_ids": ["id-1", "id-2", "id-3"]
        }

        with patch.object(client, "_request_data", return_value=mock_response):
            result = client.get_group_ids(
                "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"
            )

        assert result == ["id-1", "id-2", "id-3"]

    def test_returns_empty_list_when_no_ids(self, client):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"all_group_canonical_ids": None}

        with patch.object(client, "_request_data", return_value=mock_response):
            result = client.get_group_ids(
                "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"
            )

        assert result == []

    def test_uses_correct_params(self, client):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"all_group_canonical_ids": []}

        with patch.object(
            client, "_request_data", return_value=mock_response
        ) as mock_req:
            client.get_group_ids("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")

        call_kwargs = mock_req.call_args
        assert "messages/groups" in call_kwargs.kwargs.get(
            "api_url", call_kwargs[1].get("api_url", "")
        )
        params = call_kwargs.kwargs.get("params", call_kwargs[1].get("params", {}))
        assert params["flagged__eq"] is True
        assert params["created_at__gte"] == "2026-01-01T00:00:00Z"
        assert params["created_at__lt"] == "2026-01-02T00:00:00Z"

    def test_builds_url_with_v1(self, client):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"all_group_canonical_ids": []}

        with patch.object(
            client, "_request_data", return_value=mock_response
        ) as mock_req:
            client.get_group_ids("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")

        api_url = mock_req.call_args[1].get("api_url") or mock_req.call_args.kwargs.get(
            "api_url"
        )
        assert "/v1/messages/groups" in api_url


class TestGetSingleGroup:
    """Test get_single_group method."""

    def test_returns_group_data(self, client):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "id": "group-123",
            "subjects": ["Phishing email"],
            "attack_score_verdict": "malicious",
        }

        with patch.object(client, "_request_data", return_value=mock_response):
            result = client.get_single_group("group-123")

        assert result["id"] == "group-123"
        assert result["attack_score_verdict"] == "malicious"

    def test_maps_data_model_to_mdm(self, client):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "id": "group-123",
            "data_model": {"sender": {"email": {"email": "evil@phish.com"}}},
        }

        with patch.object(client, "_request_data", return_value=mock_response):
            result = client.get_single_group("group-123")

        assert "MDM" in result
        assert result["MDM"]["sender"]["email"]["email"] == "evil@phish.com"

    def test_does_not_overwrite_existing_mdm(self, client):
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "id": "group-123",
            "data_model": {"new": "data"},
            "MDM": {"existing": "data"},
        }

        with patch.object(client, "_request_data", return_value=mock_response):
            result = client.get_single_group("group-123")

        assert result["MDM"] == {"existing": "data"}

    def test_returns_none_on_failure(self, client):
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.text = "Not found"

        with patch.object(client, "_request_data", return_value=mock_response):
            result = client.get_single_group("nonexistent")

        assert result is None

    def test_returns_none_on_exception(self, client):
        with patch.object(
            client, "_request_data", side_effect=Exception("network error")
        ):
            result = client.get_single_group("group-123")

        assert result is None


class TestRequestData:
    """Test the internal _request_data method."""

    def test_successful_request(self, client):
        mock_response = Mock()
        mock_response.raise_for_status = Mock()

        with patch.object(client.session, "get", return_value=mock_response):
            result = client._request_data("https://api.example.com/v1/test")

        assert result == mock_response

    def test_request_timeout(self, client):
        with patch.object(client.session, "get") as mock_get:
            client._request_data("https://api.example.com/v1/test")
            mock_get.assert_called_once_with(
                "https://api.example.com/v1/test", params=None, timeout=30
            )

    def test_request_exception_returns_none(self, client):
        import requests

        with patch.object(
            client.session, "get", side_effect=requests.RequestException("timeout")
        ):
            result = client._request_data("https://api.example.com/v1/test")

        assert result is None
