import json
from unittest.mock import patch

import pytest
import requests
from connectors_sdk import (
    ApiClientError,
    ApiForbiddenError,
    ApiNotFoundError,
    ApiServerError,
)
from malpedia_services import MalpediaClient

API_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/"


def make_response(status_code: int, body) -> requests.Response:
    """Build a JSON response, as Malpedia sends them."""
    response = requests.Response()
    response.status_code = status_code
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(body).encode()
    return response


@pytest.fixture
def mock_request():
    """Mock the HTTP layer of the client session."""
    with patch.object(requests.Session, "request") as mock:
        yield mock


class TestMalpediaClient:

    def test_client_with_api_key(self):
        client = MalpediaClient(api_key="test-api-key")

        assert client.unauthenticated is False
        assert client._session.headers["Authorization"] == "apitoken test-api-key"

    @pytest.mark.parametrize("api_key", [None, ""], ids=["--None", "--Empty"])
    def test_client_without_api_key(self, api_key):
        client = MalpediaClient(api_key=api_key)

        assert client.unauthenticated is True
        assert "Authorization" not in client._session.headers

    def test_client_timeout(self, mock_request):
        mock_request.return_value = make_response(200, {"version": 1})

        MalpediaClient().get_version()

        assert mock_request.call_args.kwargs["timeout"] == 30

    def test_check_api_key_valid(self, mock_request):
        mock_request.return_value = make_response(200, {"detail": "Valid token."})

        MalpediaClient(api_key="test-api-key").check_api_key()

        mock_request.assert_called_once()
        assert mock_request.call_args.args == ("GET", API_URL + "check/apikey")

    def test_check_api_key_rejected(self, mock_request):
        # Real Malpedia answer to an invalid key: 403, not 401.
        mock_request.return_value = make_response(403, {"detail": "Invalid token."})

        with pytest.raises(ApiForbiddenError):
            MalpediaClient(api_key="test-api-key").check_api_key()

    def test_check_api_key_unexpected_answer(self, mock_request):
        mock_request.return_value = make_response(200, {"detail": "Something else"})

        with pytest.raises(ApiClientError):
            MalpediaClient(api_key="test-api-key").check_api_key()

    @pytest.mark.parametrize(
        "method, args, path, body, expected",
        [
            ("get_version", (), "get/version", {"version": 26649}, 26649),
            (
                "get_families",
                (),
                "get/families",
                {"win.emotet": {"uuid": "1"}},
                {"win.emotet": {"uuid": "1"}},
            ),
            (
                "get_yara_rules",
                ("win.emotet",),
                "get/yara/win.emotet",
                {"tlp_white": {"rule.yar": "rule a {}"}},
                {"tlp_white": {"rule.yar": "rule a {}"}},
            ),
            (
                "get_samples",
                ("win.emotet",),
                "list/samples/win.emotet",
                [{"sha256": "a" * 64}],
                [{"sha256": "a" * 64}],
            ),
            (
                "get_actor",
                ("apt28",),
                "get/actor/apt28",
                {"value": "APT28"},
                {"value": "APT28"},
            ),
        ],
        ids=["--Version", "--Families", "--Yara", "--Samples", "--Actor"],
    )
    def test_getters(self, mock_request, method, args, path, body, expected):
        mock_request.return_value = make_response(200, body)

        result = getattr(MalpediaClient(), method)(*args)

        assert result == expected
        assert mock_request.call_args.args == ("GET", API_URL + path)

    @pytest.mark.parametrize(
        "status_code, body, expected_error",
        [
            (404, {"detail": "No Actor matches the given query."}, ApiNotFoundError),
            (500, {"detail": "Server error"}, ApiServerError),
        ],
        ids=["--404-Not-Found", "--500-Server-Error"],
    )
    def test_http_errors_raise(self, mock_request, status_code, body, expected_error):
        mock_request.return_value = make_response(status_code, body)

        with pytest.raises(expected_error):
            MalpediaClient().get_actor("unknown")

    @pytest.mark.parametrize(
        "network_error",
        [
            requests.exceptions.ProxyError("Unable to connect to proxy"),
            requests.exceptions.ConnectTimeout("Connection timed out"),
            requests.exceptions.ConnectionError("Name or service not known"),
        ],
        ids=["--Proxy", "--Timeout", "--DNS"],
    )
    def test_network_errors_raise(self, mock_request, network_error):
        mock_request.side_effect = network_error

        with pytest.raises(type(network_error)):
            MalpediaClient(api_key="test-api-key").check_api_key()
