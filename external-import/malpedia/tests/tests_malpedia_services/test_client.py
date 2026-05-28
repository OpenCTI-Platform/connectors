from unittest.mock import Mock, patch

import pytest
import requests
from malpedia_services import MalpediaClient


class MockMalpediaClient(MalpediaClient):
    """Skip real authentication request for tests."""

    def token_check(self) -> bool:
        return self.api_key is not None


class TestMalpediaClient:

    @pytest.fixture(scope="class")
    def mock_helper(self):
        """Mock `OpenCTIConnectorHelper` instance as it's used only for logs."""
        return Mock()

    @pytest.mark.parametrize(
        "query_response, expected_result",
        [
            ({"detail": "Invalid token."}, False),
            ({"detail": "Valid token."}, True),
        ],
        ids=[
            "--Token--Invalid",
            "--Token--Valid",
        ],
    )
    def test_token_check(self, mock_helper, query_response, expected_result):
        # Create an instance of `MalpediaClient` without api key (to skip validation)
        malpedia_client = MalpediaClient(mock_helper, api_key=None)

        with patch.object(malpedia_client, "query") as mock_query:
            # Add api_key and mock authentication request's response
            malpedia_client.api_key = "test-api-key"
            mock_query.return_value = query_response

            assert malpedia_client.token_check() == expected_result

    @pytest.mark.parametrize(
        "api_key, response_data, expected_result",
        [
            (
                "test-api-key",
                {"data": "fake_data_unauthenticated"},
                {"data": "fake_data_unauthenticated"},
            ),
            (
                None,
                {"data": "fake_data_authenticated"},
                {"data": "fake_data_authenticated"},
            ),
            (
                "test-api-key",
                requests.exceptions.RequestException(),
                None,
            ),
            (
                None,
                requests.exceptions.RequestException(),
                None,
            ),
        ],
        ids=[
            "--Unauthenticated--Success",
            "--Authenticated--Success",
            "--Unauthenticated--RequestException",
            "--Authenticated--RequestException",
        ],
    )
    def test_query(self, mock_helper, api_key, response_data, expected_result):
        malpedia_client = MockMalpediaClient(mock_helper, api_key=api_key)

        with patch.object(malpedia_client, "api_response") as mock_api_response:
            mock_api_response.return_value = response_data

            result = malpedia_client.query("fake_endpoint")
            if isinstance(result, requests.exceptions.RequestException):
                assert expected_result is None
            else:
                assert result == expected_result

    @pytest.mark.parametrize(
        "api_key, status_code, expected_result",
        [
            ("test-api-key", 403, {"detail": "Invalid token."}),
            (None, 403, {"detail": "Invalid token."}),
            ("test-api-key", 404, None),
            (None, 404, None),
            ("test-api-key", 429, {"available_in": "16 seconds"}),
            (None, 429, {"available_in": "16 seconds"}),
            ("test-api-key", 200, {"data": "fake_data"}),
            (None, 200, {"data": "fake_data"}),
            ("test-api-key", 500, None),
            (None, 500, None),
        ],
        ids=[
            "--Authenticated--403-Invalid-token",
            "--Unauthenticated--403-Invalid-token",
            "--Authenticated--404-Invalid-token",
            "--Unauthenticated--404-Invalid-token",
            "--Authenticated--429-Too-Many-Requests",
            "--Unauthenticated--429-Too-Many-Requests",
            "--Authenticated--200-Ok",
            "--Unauthenticated--200-Ok",
            "--Authenticated--500-Internal-Server-Error",
            "--Unauthenticated--500-Internal-Server-Error",
        ],
    )
    def test_api_response(self, mock_helper, api_key, status_code, expected_result):
        malpedia_client = MockMalpediaClient(mock_helper, api_key=api_key)

        with patch("requests.get") as mock_get, patch("time.sleep") as mock_sleep:
            mock_get.return_value.status_code = status_code

            if status_code == 403:
                mock_get.return_value.text = '{"detail": "Invalid token."}'
                mock_get.return_value.json.return_value = expected_result
            elif status_code == 404:
                mock_get.return_value.reason = "No Found"
            elif status_code == 429:
                mock_get.return_value.text = '{"available_in": "16 seconds"}'
            elif status_code == 200:
                mock_get.return_value.json.return_value = expected_result
            else:
                pass

            result = malpedia_client.api_response("fake_url", 0)

            # Check if time.sleep was called if status code is 429
            if status_code == 429:
                mock_sleep.assert_called_once()
                assert result is None
            else:
                mock_sleep.assert_not_called()
                assert result == expected_result

    def test_current_version(self, mock_helper):
        malpedia_client = MockMalpediaClient(mock_helper)

        with patch.object(malpedia_client, "query", return_value={"version": 10}):
            result = malpedia_client.current_version()
            assert result == 10
