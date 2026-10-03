# pragma: no cover
# type: ignore
"""Tests of the hunt HTTP client base."""

from unittest.mock import MagicMock, patch

import pytest
import requests
from connectors_sdk.connectors.internal_hunt import (
    HuntApiClient,
    HuntExecutionError,
    HuntTimeoutError,
    RunDeadline,
    api_error_message,
)


def _response(status_code, json_data=None, text=""):
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.ok = status_code < 400
    response.headers = {"Content-Type": "application/json"} if json_data else {}
    response.json.return_value = json_data
    if json_data is None:
        response.json.side_effect = ValueError("no json")
    response.text = text
    return response


@pytest.fixture
def client():
    return HuntApiClient("https://siem.example.com", max_retries=0)


@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param({"message": " Bad query "}, "Bad query", id="message"),
        pytest.param(
            {"error": {"type": "parsing_exception", "reason": "line 1"}},
            "line 1",
            id="elastic",
        ),
        pytest.param(
            {"error": {"code": "BadArgumentError", "message": "Syntax"}},
            "Syntax",
            id="azure",
        ),
        pytest.param(
            {"messages": [{"type": "FATAL", "text": "Unknown"}, {"type": "WARN"}]},
            "Unknown",
            id="splunk",
        ),
        pytest.param(
            {"errors": ["first", {"detail": "second"}]}, "first; second", id="list"
        ),
        pytest.param("  plain\n text  ", "plain text", id="text"),
        pytest.param({"code": 7}, '{"code": 7}', id="unknown_shape"),
        pytest.param({"error": {"code": 7}}, '{"error": {"code": 7}}', id="no_text"),
        pytest.param(None, None, id="none"),
        pytest.param("", None, id="empty_text"),
        pytest.param({}, None, id="empty_object"),
        pytest.param([], None, id="empty_list"),
    ],
)
def test_api_error_message_extracts_the_platform_message(body, expected):
    # Given/When/Then the readable message of the error body is extracted
    assert api_error_message(body) == expected


def test_api_error_message_is_capped_and_stops_at_depth():
    # Given a long message and a deeply nested body
    nested = {"error": {"error": {"error": {"error": {"error": {"message": "deep"}}}}}}

    # When/Then the message is truncated and the nesting depth bounded
    assert api_error_message({"message": "x" * 600}) == "x" * 500
    assert api_error_message({"message": "abcdef"}, max_length=3) == "abc"
    assert "deep" in api_error_message(nested)
    assert api_error_message(nested).startswith("{")


def test_hunt_request_returns_the_decoded_body(client):
    # Given a platform answering with JSON
    with patch.object(client._session, "request") as request:
        request.return_value = _response(200, {"hits": 3})

        # When the call is made within the deadline
        body = client.hunt_request(
            "POST", "/search", RunDeadline(30), "The search", json={"q": "x"}
        )

    # Then the body is decoded and the call bounded by the deadline
    assert body == {"hits": 3}
    _, kwargs = request.call_args
    assert 1 <= kwargs["timeout"] <= 30
    assert kwargs["json"] == {"q": "x"}


def test_hunt_request_caps_the_request_timeout(client):
    # Given a long deadline and a short maximum timeout
    with patch.object(client._session, "request") as request:
        request.return_value = _response(204)

        # When/Then the request timeout is the maximum timeout
        assert (
            client.hunt_request(
                "GET", "/x", RunDeadline(600), "The call", max_timeout=5
            )
            is None
        )
    assert request.call_args.kwargs["timeout"] == 5


def test_hunt_request_refuses_expired_deadlines(client):
    # Given an expired deadline
    with patch.object(client._session, "request") as request:
        # When/Then nothing is sent and the run times out
        with pytest.raises(HuntTimeoutError, match="The search"):
            client.hunt_request("GET", "/x", RunDeadline(0), "The search")
    request.assert_not_called()


@pytest.mark.parametrize(
    "response, expected",
    [
        pytest.param(
            _response(400, {"error": {"reason": "bad syntax"}}),
            r"The search failed \(HTTP 400 on GET /x\): bad syntax",
            id="with_details",
        ),
        pytest.param(
            _response(401),
            r"The search failed \(Unauthorized \(401\) on GET /x\)$",
            id="without_details",
        ),
    ],
)
def test_hunt_request_maps_http_errors(client, response, expected):
    # Given a platform rejecting the call
    with patch.object(client._session, "request", return_value=response):
        # When/Then a hunt execution error explains the failure
        with pytest.raises(HuntExecutionError, match=expected):
            client.hunt_request("GET", "/x", RunDeadline(30), "The search")


def test_hunt_request_maps_network_errors(client):
    # Given a platform that times out, then cannot be reached
    with patch.object(
        client._session,
        "request",
        side_effect=[requests.ReadTimeout("slow"), requests.ConnectionError("down")],
    ):
        # When/Then the timeout and the network error are hunt errors
        with pytest.raises(HuntTimeoutError, match="did not answer"):
            client.hunt_request("GET", "/x", RunDeadline(30), "The search")
        with pytest.raises(HuntExecutionError, match="ConnectionError: down"):
            client.hunt_request("GET", "/x", RunDeadline(30), "The search")


def test_cleanup_request_never_raises(client):
    # Given a cleanup call that succeeds, then fails twice
    with patch.object(
        client._session,
        "request",
        side_effect=[
            _response(200, {"ok": True}),
            _response(404),
            requests.ConnectionError("down"),
        ],
    ) as request:
        # When/Then success returns nothing and failures return the error
        assert client.cleanup_request("DELETE", "/job/1", "The deletion") is None
        assert "The deletion failed: Not found" in client.cleanup_request(
            "DELETE", "/job/1", "The deletion"
        )
        assert client.cleanup_request(
            "DELETE", "/job/1", "The deletion", timeout=2
        ) == ("The deletion failed: down")
    assert request.call_args.kwargs["timeout"] == 2
