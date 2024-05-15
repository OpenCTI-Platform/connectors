from unittest.mock import Mock, patch

import pytest
import requests
from malpedia_services.client import MalpediaClient


@pytest.mark.usefixtures("setup_config")
class TestMalpediaClient:

    @pytest.fixture(scope="class")
    def mock_helper(self):
        return Mock()

    @pytest.fixture(scope="class")
    def api_key(self):
        return ""

    @pytest.fixture(scope="class")
    def malpedia_client(self, mock_helper, api_key):
        return MalpediaClient(mock_helper, api_key)

    @pytest.fixture(scope="class")
    def setup_config(self, request, api_key):
        """
        Setup configuration for class method
        Create fake pycti OpenCTI helper
        """
        request.cls.mock_helper = Mock()
        request.cls.api_key = api_key
        request.cls.mock_client = MalpediaClient(
            request.cls.mock_helper, request.cls.api_key
        )
        yield

    @pytest.mark.parametrize(
        "query_response, expected_result",
        [({"detail": "Invalid token."}, False), ({"detail": "Valid token."}, True)],
        ids=[
            "--Token--Invalid",
            "--Token--Valid",
        ],
    )
    def test_token_check(self, malpedia_client, query_response, expected_result):
        with patch.object(malpedia_client, "query", return_value=query_response):
            assert malpedia_client.token_check() == expected_result

    @pytest.mark.parametrize(
        "unauthenticated, response_data, expected_result",
        [
            (
                True,
                {"data": "fake_data_unauthenticated"},
                {"data": "fake_data_unauthenticated"},
            ),
            (
                False,
                {"data": "fake_data_authenticated"},
                {"data": "fake_data_authenticated"},
            ),
            (True, requests.exceptions.RequestException(), None),
            (False, requests.exceptions.RequestException(), None),
        ],
        ids=[
            "--Unauthenticated--Success",
            "--Authenticated--Success",
            "--Unauthenticated--RequestException",
            "--Authenticated--RequestException",
        ],
    )
    def test_query(
        self, malpedia_client, unauthenticated, response_data, expected_result
    ):
        with patch.object(malpedia_client, "api_response") as mock_api_response:
            mock_api_response.return_value = response_data
            malpedia_client.unauthenticated = unauthenticated

            result = malpedia_client.query("fake_endpoint")
            if isinstance(result, requests.exceptions.RequestException):
                assert expected_result is None
            else:
                assert result == expected_result

    @pytest.mark.parametrize(
        "authenticated, status_code, expected_result",
        [
            (True, 403, {"detail": "Invalid token."}),
            (False, 403, {"detail": "Invalid token."}),
            (True, 404, None),
            (False, 404, None),
            (True, 429, None),
            (False, 429, None),
            (True, 200, {"data": "fake_data"}),
            (False, 200, {"data": "fake_data"}),
            (True, 500, None),
            (False, 500, None),
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
    def test_api_response(
        self, malpedia_client, authenticated, status_code, expected_result
    ):
        with patch("malpedia_services.client.requests.get") as mock_get:
            mock_get.return_value.status_code = status_code
            if status_code == 403:
                mock_get.return_value.text = '{"detail": "Invalid token."}'
                mock_get.return_value.json.return_value = expected_result
            elif status_code == 404:
                mock_get.return_value.reason = "No Found"
            elif status_code == 200:
                mock_get.return_value.json.return_value = expected_result
            else:
                pass

            result = malpedia_client.api_response("fake_url", 0, auth=authenticated)
            assert result == expected_result

    def test_current_version(self, malpedia_client):
        with patch.object(malpedia_client, "query", return_value={"version": 10}):

            result = malpedia_client.current_version()
            assert result == 10
