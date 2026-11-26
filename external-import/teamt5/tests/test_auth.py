"""Unit tests for ``teamt5_services.auth.JWTClientCredentialAuth``."""

from unittest.mock import MagicMock, patch

import pytest
import requests
from requests.adapters import BaseAdapter
from teamt5_services.auth import JWTClientCredentialAuth, TokenRequestError

TOKEN_URL = "https://api.example.org/oauth/token"
API_URL = "https://api.example.org/api/v2/reports"


class _FakeAdapter(BaseAdapter):
    """A transport adapter answering with the given status codes, in order, and
    recording the ``Authorization`` header of each request it sends."""

    def __init__(self, status_codes):
        super().__init__()
        self.status_codes = list(status_codes)
        self.sent_tokens = []

    def send(self, request, **kwargs):
        self.sent_tokens.append(request.headers["Authorization"])
        response = requests.Response()
        response.status_code = self.status_codes.pop(0)
        response._content = b"{}"
        response.request = request
        response.url = request.url
        response.connection = self
        return response

    def close(self):
        pass


def _session(auth, status_codes):
    session = requests.Session()
    session.auth = auth
    adapter = _FakeAdapter(status_codes)
    session.mount("https://", adapter)
    return session, adapter


def _token_response(access_token, expires_in=None):
    """A token endpoint response carrying ``access_token`` and ``expires_in``."""
    body = {"access_token": access_token}
    if expires_in is not None:
        body["expires_in"] = expires_in
    response = MagicMock(spec=requests.Response)
    response.json.return_value = body
    return response


@pytest.fixture
def token_post():
    """``requests.post`` as the auth calls it, to the token endpoint."""
    with patch("teamt5_services.auth.requests.post") as post:
        yield post


@pytest.fixture
def clock():
    """``time.monotonic`` as the auth reads it, starting at 1000."""
    with patch("teamt5_services.auth.time.monotonic", return_value=1000.0) as clock:
        yield clock


@pytest.fixture
def auth():
    return JWTClientCredentialAuth(TOKEN_URL, "client-id", "client-secret", leeway=60)


def test_first_request_gets_a_token(auth, token_post, clock):
    token_post.return_value = _token_response("token-1", expires_in=3600)
    session, adapter = _session(auth, [200])

    response = session.get(API_URL)

    assert response.status_code == 200
    token_post.assert_called_once_with(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": "client-id",
            "client_secret": "client-secret",
        },
        timeout=10,
    )
    assert adapter.sent_tokens == ["Bearer token-1"]


def test_token_is_reused_while_valid(auth, token_post, clock):
    token_post.return_value = _token_response("token-1", expires_in=3600)
    session, adapter = _session(auth, [200, 200])

    session.get(API_URL)
    clock.return_value = 1000.0 + 3600 - 61  # just outside the leeway
    session.get(API_URL)

    token_post.assert_called_once()
    assert adapter.sent_tokens == ["Bearer token-1", "Bearer token-1"]


def test_token_is_refreshed_before_it_expires(auth, token_post, clock):
    # The lifetime comes from the token response, the leeway is 60 seconds
    token_post.side_effect = [
        _token_response("token-1", expires_in=300),
        _token_response("token-2", expires_in=300),
    ]
    session, adapter = _session(auth, [200, 200])

    session.get(API_URL)
    clock.return_value = 1000.0 + 300 - 60  # inside the leeway
    session.get(API_URL)

    assert token_post.call_count == 2
    assert adapter.sent_tokens == ["Bearer token-1", "Bearer token-2"]


def test_missing_expires_in_uses_the_default_lifetime(token_post, clock):
    auth = JWTClientCredentialAuth(
        TOKEN_URL, "client-id", "client-secret", leeway=60, default_expires_in=120
    )
    token_post.return_value = _token_response("token-1")
    session, _ = _session(auth, [200, 200])

    session.get(API_URL)
    clock.return_value = 1000.0 + 60  # 120 - 60 seconds of leeway
    session.get(API_URL)

    assert token_post.call_count == 2


def test_401_refreshes_the_token_and_retries_once(auth, token_post, clock):
    token_post.side_effect = [
        _token_response("token-1", expires_in=3600),
        _token_response("token-2", expires_in=3600),
    ]
    session, adapter = _session(auth, [401, 200])

    response = session.get(API_URL)

    assert response.status_code == 200
    assert adapter.sent_tokens == ["Bearer token-1", "Bearer token-2"]
    assert [r.status_code for r in response.history] == [401]
    assert response.request.headers["Authorization"] == "Bearer token-2"


def test_second_401_is_returned_without_another_retry(auth, token_post, clock):
    token_post.side_effect = [
        _token_response("token-1", expires_in=3600),
        _token_response("token-2", expires_in=3600),
    ]
    session, adapter = _session(auth, [401, 401])

    response = session.get(API_URL)

    assert response.status_code == 401
    assert token_post.call_count == 2
    assert adapter.sent_tokens == ["Bearer token-1", "Bearer token-2"]


def test_401_with_a_token_already_replaced_retries_without_refreshing(
    auth, token_post, clock
):
    # Another thread refreshed the token while this request was in flight
    token_post.return_value = _token_response("token-1", expires_in=3600)
    session, adapter = _session(auth, [200, 401, 200])
    session.get(API_URL)

    def replace_token_then_answer(request, **kwargs):
        auth.access_token = "token-2"
        return _FakeAdapter.send(adapter, request, **kwargs)

    with patch.object(adapter, "send", side_effect=replace_token_then_answer):
        response = session.get(API_URL)

    assert response.status_code == 200
    token_post.assert_called_once()
    assert adapter.sent_tokens == ["Bearer token-1", "Bearer token-1", "Bearer token-2"]


def test_token_request_failure_raises(auth, token_post, clock):
    http_error = requests.HTTPError("401 Unauthorized")
    failure = MagicMock(spec=requests.Response)
    failure.raise_for_status.side_effect = http_error
    token_post.return_value = failure
    session, adapter = _session(auth, [200])

    with pytest.raises(TokenRequestError, match=TOKEN_URL) as info:
        session.get(API_URL)
    assert info.value.__cause__ is http_error
    # Not a ``RequestException``: a caller can tell it from a failed API request
    assert not isinstance(info.value, requests.RequestException)
    assert adapter.sent_tokens == []


def test_network_failure_raises(auth, token_post, clock):
    token_post.side_effect = requests.ConnectionError("dns down")
    session, _ = _session(auth, [200])

    with pytest.raises(TokenRequestError) as info:
        session.get(API_URL)
    assert isinstance(info.value.__cause__, requests.ConnectionError)


@pytest.mark.parametrize(
    "body, cause",
    [
        pytest.param({"expires_in": 3600}, KeyError, id="missing-access-token"),
        pytest.param(
            {"access_token": "t", "expires_in": None}, ValueError, id="null-expires-in"
        ),
        pytest.param(
            {"access_token": "t", "expires_in": "soon"},
            ValueError,
            id="text-expires-in",
        ),
        pytest.param(["not", "an", "object"], ValueError, id="not-an-object"),
        pytest.param(None, ValueError, id="null-body"),
    ],
)
def test_invalid_token_response_raises(auth, token_post, clock, body, cause):
    response = MagicMock(spec=requests.Response)
    response.json.return_value = body
    token_post.return_value = response
    session, _ = _session(auth, [200])

    with pytest.raises(TokenRequestError) as info:
        session.get(API_URL)
    assert isinstance(info.value.__cause__, cause)
    # A failed exchange leaves no token behind
    assert auth.access_token is None


def test_body_that_is_not_json_raises(auth, token_post, clock):
    response = MagicMock(spec=requests.Response)
    response.json.side_effect = requests.JSONDecodeError("Expecting value", "<html>", 0)
    token_post.return_value = response
    session, _ = _session(auth, [200])

    with pytest.raises(TokenRequestError) as info:
        session.get(API_URL)
    assert isinstance(info.value.__cause__, ValueError)
