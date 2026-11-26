"""Unit tests for ``teamt5_services.adapters.RetryingAdapter``.

``HTTPAdapter.send``, which the adapter calls for each attempt, is replaced by a
mock answering with the given responses or exceptions, in order.
"""

from unittest.mock import patch

import pytest
import requests
from requests.adapters import HTTPAdapter
from teamt5_services.adapters import RetryingAdapter, is_retried_status


class _Response:
    """A response whose body read raises ``body_error``, if any."""

    def __init__(self, status_code, body_error=None):
        self.status_code = status_code
        self.body_error = body_error
        self.closed = False

    @property
    def content(self):
        if self.body_error is not None:
            raise self.body_error
        return b"{}"

    def close(self):
        self.closed = True


@pytest.fixture
def sleep():
    with patch("teamt5_services.adapters.time.sleep") as sleep:
        yield sleep


def _send(outcomes, adapter=None, method="GET"):
    """Send a request through ``adapter`` while each attempt gets the next outcome.

    :return: The result of ``send``, and the mock of ``HTTPAdapter.send``.
    """
    adapter = adapter or RetryingAdapter()
    request = requests.Request(
        method, "https://api.example.org/api/v2/reports"
    ).prepare()
    with patch.object(HTTPAdapter, "send", side_effect=outcomes) as send:
        result = adapter.send(request, timeout=15)
    return result, send


def _sleeps(sleep):
    return [call.args[0] for call in sleep.call_args_list]


def test_success_is_returned_at_once(sleep):
    ok = _Response(200)

    response, send = _send([ok])

    assert response is ok
    send.assert_called_once()
    assert send.call_args.kwargs == {"timeout": 15}
    sleep.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(requests.exceptions.ReadTimeout("read"), id="read-timeout"),
        pytest.param(
            requests.exceptions.ConnectTimeout("connect"), id="connect-timeout"
        ),
        pytest.param(requests.ConnectionError("reset"), id="connection-error"),
    ],
)
def test_network_failure_is_retried(sleep, failure):
    ok = _Response(200)

    response, send = _send([failure, ok])

    assert response is ok
    assert send.call_count == 2
    assert _sleeps(sleep) == [1]


def test_connection_cut_while_reading_the_body_is_retried(sleep):
    cut = _Response(200, body_error=requests.exceptions.ChunkedEncodingError("cut"))
    ok = _Response(200)

    response, send = _send([cut, ok])

    assert response is ok
    assert send.call_count == 2


def test_server_errors_are_retried_with_a_growing_wait(sleep):
    first, second, ok = _Response(500), _Response(503), _Response(200)

    response, send = _send([first, second, ok])

    assert response is ok
    assert send.call_count == 3
    assert _sleeps(sleep) == [1, 2]
    # The failed responses are released before the next attempt
    assert first.closed and second.closed


def test_last_server_error_is_returned_when_every_attempt_fails(sleep):
    responses = [_Response(502) for _ in range(5)]

    response, send = _send(responses)

    assert response is responses[-1]
    assert send.call_count == 5
    assert _sleeps(sleep) == [1, 2, 4, 8]


def test_last_exception_is_raised_when_every_attempt_fails(sleep):
    failures = [requests.exceptions.ReadTimeout(f"read {i}") for i in range(5)]

    with pytest.raises(requests.exceptions.ReadTimeout, match="read 4"):
        _send(failures)

    assert _sleeps(sleep) == [1, 2, 4, 8]


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 429])
def test_client_errors_are_not_retried(sleep, status_code):
    response, send = _send([_Response(status_code)])

    assert response.status_code == status_code
    send.assert_called_once()
    sleep.assert_not_called()


def test_ssl_error_is_not_retried(sleep):
    with pytest.raises(requests.exceptions.SSLError):
        _send([requests.exceptions.SSLError("bad certificate"), _Response(200)])

    sleep.assert_not_called()


def test_attempts_and_backoff_are_configurable(sleep):
    adapter = RetryingAdapter(max_attempts=2, backoff=0.5)

    response, send = _send([_Response(500), _Response(500)], adapter)

    assert response.status_code == 500
    assert send.call_count == 2
    assert _sleeps(sleep) == [0.5]


def test_head_request_is_retried(sleep):
    response, send = _send([_Response(503), _Response(200)], method="HEAD")

    assert response.status_code == 200
    assert send.call_count == 2


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_other_methods_are_sent_once(sleep, method):
    response, send = _send([_Response(503), _Response(200)], method=method)

    # The server error is returned as is: the request is never sent twice
    assert response.status_code == 503
    send.assert_called_once()
    sleep.assert_not_called()


def test_other_methods_raise_at_once(sleep):
    with pytest.raises(requests.exceptions.ReadTimeout):
        _send([requests.exceptions.ReadTimeout("slow"), _Response(200)], method="POST")

    sleep.assert_not_called()


@pytest.mark.parametrize("status_code", [500, 502, 503, 504, 507, 520, 522, 524, 599])
def test_server_errors_are_retried(sleep, status_code):
    response, send = _send([_Response(status_code), _Response(200)])

    assert response.status_code == 200
    assert send.call_count == 2


@pytest.mark.parametrize("status_code", [501, 505, 511])
def test_permanent_server_errors_are_not_retried(sleep, status_code):
    response, send = _send([_Response(status_code), _Response(200)])

    assert response.status_code == status_code
    send.assert_called_once()
    sleep.assert_not_called()


@pytest.mark.parametrize(
    "status_code, retried",
    [(200, False), (404, False), (429, False), (499, False), (500, True), (501, False)],
)
def test_is_retried_status(status_code, retried):
    assert is_retried_status(status_code) is retried
