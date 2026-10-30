import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import jwt
from comlaude import API_BASE_URL, ComLaudeAuth, ComLaudeSearch


def _make_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.text = json.dumps(payload)
    response.json.return_value = payload
    return response


def _make_token():
    expiration = datetime.now() + timedelta(days=2)
    access_token = jwt.encode(
        {"exp": int(expiration.timestamp())},
        "test-signing-key-long-enough-for-hs256",
        algorithm="HS256",
    )
    return {"access_token": access_token}


def test_auth_requests_token_with_default_session_settings():
    """Test that the token request relies on the session default settings."""
    http_session = MagicMock()
    http_session.request.return_value = _make_response({"data": _make_token()})

    auth = ComLaudeAuth(
        "test-user", "test-password", "test-api-key", http_session=http_session
    )

    http_session.request.assert_called_once()
    call = http_session.request.call_args
    assert call.args == ("POST", f"{API_BASE_URL}/api_login")
    assert "verify" not in call.kwargs
    assert auth.authorization_header["authorization"].startswith("Bearer ")


def test_search_requests_domains_with_default_session_settings():
    """Test that the search request relies on the session default settings."""
    comlaude_auth = MagicMock()
    comlaude_auth.api_base_url = API_BASE_URL
    comlaude_auth.authorization_header = {"authorization": "Bearer token"}
    http_session = MagicMock()
    http_session.request.return_value = _make_response(
        {"data": [], "pagination": {"next": None}}
    )

    search = ComLaudeSearch(
        comlaude_auth,
        "test-group-id",
        "1970-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        http_session=http_session,
    )

    http_session.request.assert_called_once()
    call = http_session.request.call_args
    assert call.args == (
        "POST",
        f"{API_BASE_URL}/groups/test-group-id/domains/search",
    )
    assert "verify" not in call.kwargs
    assert call.kwargs["headers"]["authorization"] == "Bearer token"
    assert search.has_next is False
