"""Unit tests for AiTMFeedClient."""

from unittest.mock import Mock, patch

import pytest
from lab539_aitm_connector.api_client import AiTMFeedClient


def _secret(value):
    """Stand-in for a Pydantic SecretStr."""
    secret = Mock()
    secret.get_secret_value.return_value = value
    return secret


class TestGetLastEvent:
    """Tests for AiTMFeedClient.get_last_event."""

    def test_returns_eventid_on_success(self):
        """Should return the eventid from a successful response."""
        client = AiTMFeedClient(
            api_key=_secret("test-key"), base_url="https://aitm.lab539.io/v1.0"
        )
        mock_response = Mock()
        mock_response.json.return_value = {"eventid": "test-event-id"}
        mock_response.raise_for_status = Mock()

        with patch.object(client.session, "get", return_value=mock_response):
            result = client.get_last_event()

        assert result == "test-event-id"

    def test_returns_none_on_failure(self):
        """Should return None when the request fails."""
        import requests

        client = AiTMFeedClient(
            api_key=_secret("test-key"), base_url="https://aitm.lab539.io/v1.0"
        )
        with patch.object(
            client.session,
            "get",
            side_effect=requests.exceptions.ConnectionError("connection error"),
        ):
            result = client.get_last_event()

        assert result is None


class TestGetRecords:
    """Tests for AiTMFeedClient.get_records."""

    def test_returns_records_on_success(self, sample_record):
        """Should return a list of records on success."""
        client = AiTMFeedClient(
            api_key=_secret("test-key"), base_url="https://aitm.lab539.io/v1.0"
        )
        mock_response = Mock()
        mock_response.json.return_value = [sample_record]
        mock_response.raise_for_status = Mock()

        with patch.object(client.session, "get", return_value=mock_response):
            result = client.get_records()

        assert len(result) == 1
        assert result[0]["eventid"] == sample_record["eventid"]

    def test_passes_after_parameter(self, sample_record):
        """Should pass the after parameter to the API."""
        client = AiTMFeedClient(
            api_key=_secret("test-key"), base_url="https://aitm.lab539.io/v1.0"
        )
        mock_response = Mock()
        mock_response.json.return_value = [sample_record]
        mock_response.raise_for_status = Mock()

        with patch.object(
            client.session, "get", return_value=mock_response
        ) as mock_get:
            client.get_records(after=1778919394)

        call_kwargs = mock_get.call_args
        assert call_kwargs[1]["params"]["after"] == "1778919394"

    def test_raises_on_connection_error(self):
        """Should raise RuntimeError on connection error."""
        import requests

        client = AiTMFeedClient(
            api_key=_secret("test-key"), base_url="https://aitm.lab539.io/v1.0"
        )
        with patch.object(
            client.session,
            "get",
            side_effect=requests.exceptions.ConnectionError(),
        ):
            with pytest.raises(RuntimeError, match="unreachable"):
                client.get_records()

    def test_raises_on_timeout(self):
        """Should raise RuntimeError on timeout."""
        import requests

        client = AiTMFeedClient(
            api_key=_secret("test-key"), base_url="https://aitm.lab539.io/v1.0"
        )
        with patch.object(
            client.session,
            "get",
            side_effect=requests.exceptions.Timeout(),
        ):
            with pytest.raises(RuntimeError, match="timed out"):
                client.get_records()
