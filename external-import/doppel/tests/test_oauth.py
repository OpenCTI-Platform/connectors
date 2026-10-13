from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest
from doppel.oauth import OAuthTokenError, OAuthTokenProvider


def _token_response(
    access_token: str = "access-token", expires_in: int = 3600
) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }
    return response


def test_token_session_sets_attribution_headers():
    provider = OAuthTokenProvider(
        token_url="https://api.doppel.test/oauth/token",
        client_id="client-id",
        client_secret="client-secret",
        audience="doppel-external",
    )

    assert provider.session.headers["x-doppel-client"] == "opencti/7.260901.0"
    assert provider.session.headers["User-Agent"] == "doppel-opencti/7.260901.0"


def test_token_is_cached_and_refreshed_before_expiry():
    now = [100.0]
    session = MagicMock()
    session.post.side_effect = [
        _token_response("token-1", expires_in=100),
        _token_response("token-2", expires_in=100),
    ]
    provider = OAuthTokenProvider(
        token_url="https://api.doppel.test/oauth/token",
        client_id="client-id",
        client_secret="client-secret",
        audience="doppel-external",
        session=session,
        clock=lambda: now[0],
    )

    assert provider.get_token() == "token-1"
    now[0] = 189.0
    assert provider.get_token() == "token-1"
    now[0] = 190.0
    assert provider.get_token() == "token-2"

    assert session.post.call_count == 2
    session.post.assert_any_call(
        "https://api.doppel.test/oauth/token",
        json={
            "client_id": "client-id",
            "client_secret": "client-secret",
            "audience": "doppel-external",
            "grant_type": "client_credentials",
        },
        timeout=30,
    )


def test_concurrent_requests_mint_one_token():
    session = MagicMock()
    session.post.return_value = _token_response()
    provider = OAuthTokenProvider(
        token_url="https://api.doppel.test/oauth/token",
        client_id="client-id",
        client_secret="client-secret",
        audience="doppel-external",
        session=session,
    )

    with ThreadPoolExecutor(max_workers=10) as executor:
        tokens = list(executor.map(lambda _: provider.get_token(), range(10)))

    assert tokens == ["access-token"] * 10
    session.post.assert_called_once()


def test_late_unauthorized_response_reuses_token_refreshed_by_another_request():
    session = MagicMock()
    session.post.side_effect = [
        _token_response("token-1"),
        _token_response("token-2"),
    ]
    provider = OAuthTokenProvider(
        token_url="https://api.doppel.test/oauth/token",
        client_id="client-id",
        client_secret="client-secret",
        audience="doppel-external",
        session=session,
    )

    rejected_token = provider.get_token()
    assert provider.refresh_after_unauthorized(rejected_token) == "token-2"
    assert provider.refresh_after_unauthorized(rejected_token) == "token-2"
    assert session.post.call_count == 2


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"access_token": "", "token_type": "Bearer", "expires_in": 3600},
        {"access_token": "token", "token_type": "MAC", "expires_in": 3600},
        {"access_token": "token", "token_type": "Bearer", "expires_in": 0},
        {"access_token": "token", "token_type": "Bearer", "expires_in": "invalid"},
    ],
)
def test_invalid_token_response_fails_closed(payload):
    response = MagicMock()
    response.json.return_value = payload
    session = MagicMock()
    session.post.return_value = response
    provider = OAuthTokenProvider(
        token_url="https://api.doppel.test/oauth/token",
        client_id="client-id",
        client_secret="client-secret",
        audience="doppel-external",
        session=session,
    )

    with pytest.raises(OAuthTokenError):
        provider.get_token()
