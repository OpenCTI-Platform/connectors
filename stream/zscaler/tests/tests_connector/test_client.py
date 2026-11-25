from unittest.mock import Mock

import pytest
import requests
from stream_connector.client import (
    LegacyAuth,
    OneApiAuth,
    ZscalerAuthenticationError,
    ZscalerClient,
    obfuscate_api_key,
)
from zscaler_responses import make_response

TOKEN = {"access_token": "token-1", "token_type": "Bearer", "expires_in": 3600}


@pytest.fixture
def no_sleep(monkeypatch):
    """Skip the retry delays (tenacity sleeps through ``time.sleep``)."""
    sleep = Mock()
    monkeypatch.setattr("time.sleep", sleep)
    return sleep


def test_base_url_should_target_production_cloud_by_default(client):
    assert client.base_url == "https://api.zsapi.net/zia/api/v1"
    assert client.auth.token_url == "https://acme.zslogin.net/oauth2/v1/token"


def test_base_url_should_include_cloud_when_set():
    client = ZscalerClient(
        logger=Mock(),
        auth=OneApiAuth(
            client_id="client-id",
            client_secret="client-secret",
            vanity_domain="acme",
            cloud="beta",
        ),
    )

    assert client.base_url == "https://api.beta.zsapi.net/zia/api/v1"


def test_authenticate_should_request_token_with_client_credentials(client):
    client.session.post.return_value = make_response(200, TOKEN)

    client.authenticate()

    _, kwargs = client.session.post.call_args
    assert client.session.post.call_args.args[0] == client.auth.token_url
    assert kwargs["data"] == {
        "grant_type": "client_credentials",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "audience": "https://api.zscaler.com",
    }
    assert client.auth._access_token == "token-1"


@pytest.mark.parametrize(
    "post_result",
    [
        pytest.param(make_response(401, {"error": "invalid_client"}), id="http_401"),
        pytest.param(make_response(200, {"unexpected": "body"}), id="no_token"),
        pytest.param(requests.ConnectionError("boom"), id="network_error"),
    ],
)
def test_authenticate_should_raise_on_failure(client, post_result):
    if isinstance(post_result, Exception):
        client.session.post.side_effect = post_result
    else:
        client.session.post.return_value = post_result

    with pytest.raises(ZscalerAuthenticationError):
        client.authenticate()


def test_request_should_send_bearer_token_and_reuse_it(client):
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.return_value = make_response(200, {"status": "ACTIVE"})

    client.request("GET", "/status")
    response = client.request("GET", "/status")

    assert response.json() == {"status": "ACTIVE"}
    assert client.session.post.call_count == 1  # token cached
    args, kwargs = client.session.request.call_args
    assert args == ("GET", "https://api.zsapi.net/zia/api/v1/status")
    assert kwargs["headers"]["Authorization"] == "Bearer token-1"


def test_request_should_refresh_expired_token(client):
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.return_value = make_response(200)
    client.request("GET", "/status")

    client.auth._token_expires_at = 0  # token expired
    client.request("GET", "/status")

    assert client.session.post.call_count == 2


def test_request_should_retry_once_with_new_token_on_401(client):
    client.session.post.side_effect = [
        make_response(200, TOKEN),
        make_response(200, {**TOKEN, "access_token": "token-2"}),
    ]
    client.session.request.side_effect = [make_response(401), make_response(200)]

    response = client.request("GET", "/status")

    assert response.status_code == 200
    assert client.session.post.call_count == 2
    _, kwargs = client.session.request.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer token-2"


def test_request_should_return_401_when_new_token_is_also_rejected(client):
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.return_value = make_response(401)

    response = client.request("GET", "/status")

    assert response.status_code == 401
    assert client.session.request.call_count == 2


def test_request_should_wait_for_rate_limit_reset_on_429(client, no_sleep):
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.side_effect = [
        make_response(429, headers={"x-ratelimit-reset": "7"}),
        make_response(200),
    ]

    response = client.request("GET", "/status")

    assert response.status_code == 200
    no_sleep.assert_called_once_with(7)


def test_request_should_return_last_429_after_max_retries(client, no_sleep):
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.return_value = make_response(429)

    response = client.request("GET", "/status")

    assert response.status_code == 429
    assert client.session.request.call_count == client.max_retries


def test_request_should_return_none_when_authentication_fails(client):
    client.session.post.return_value = make_response(401)

    assert client.request("GET", "/status") is None
    client.session.request.assert_not_called()


def test_request_should_return_none_after_repeated_network_errors(client, no_sleep):
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.side_effect = requests.ConnectionError("boom")

    assert client.request("GET", "/status") is None
    assert client.session.request.call_count == client.max_retries


@pytest.mark.parametrize(
    "first_result",
    [
        pytest.param(make_response(503, {"message": "busy"}), id="http_503"),
        pytest.param(requests.ConnectionError("boom"), id="network_error"),
    ],
)
def test_request_should_retry_transient_failures(client, no_sleep, first_result):
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.side_effect = [first_result, make_response(200)]

    response = client.request("POST", "/status/activate")

    assert response.status_code == 200
    assert client.session.request.call_count == 2


def test_request_should_refresh_token_after_rate_limit_retries(client, no_sleep):
    """A 401 after 429 responses still gets its token refresh and replay."""
    client.session.post.side_effect = [
        make_response(200, TOKEN),
        make_response(200, {**TOKEN, "access_token": "token-2"}),
    ]
    client.session.request.side_effect = [
        make_response(429),
        make_response(429),
        make_response(401),
        make_response(200),
    ]
    client.max_retries = 3

    response = client.request("GET", "/status")

    assert response.status_code == 200
    assert client.session.post.call_count == 2
    _, kwargs = client.session.request.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer token-2"


# --- Deprecated legacy API authentication ---


@pytest.fixture
def legacy_client(logger):
    zscaler_client = ZscalerClient(
        logger=logger,
        auth=LegacyAuth(
            api_base_url="https://zsapi.zscalertwo.net/",
            username="user",
            password="pass",
            api_key="abcdefghijklmnop",
        ),
    )
    zscaler_client.session = Mock()
    zscaler_client.session.cookies = requests.cookies.RequestsCookieJar()
    return zscaler_client


def _legacy_login(session, session_id="session-1"):
    def fake_post(*args, **kwargs):
        session.cookies.set("JSESSIONID", session_id)
        return make_response(200)

    return fake_post


def test_obfuscate_api_key_should_match_legacy_algorithm():
    # high = "123456", low = str(123456 >> 1) = "061728"
    assert obfuscate_api_key("abcdefghijklmnop", "1700000123456") == "bcdefgcidjek"


def test_legacy_client_should_target_legacy_api(legacy_client):
    assert legacy_client.base_url == "https://zsapi.zscalertwo.net/api/v1"


def test_legacy_authenticate_should_open_session(legacy_client):
    legacy_client.session.post.side_effect = _legacy_login(legacy_client.session)

    legacy_client.authenticate()

    args, kwargs = legacy_client.session.post.call_args
    assert args[0] == "https://zsapi.zscalertwo.net/api/v1/authenticatedSession"
    assert kwargs["json"]["username"] == "user"
    assert kwargs["json"]["password"] == "pass"
    assert kwargs["json"]["apiKey"] == obfuscate_api_key(
        "abcdefghijklmnop", kwargs["json"]["timestamp"]
    )


def test_legacy_authenticate_should_raise_without_session_cookie(legacy_client):
    legacy_client.session.post.return_value = make_response(200)

    with pytest.raises(ZscalerAuthenticationError):
        legacy_client.authenticate()


def test_legacy_request_should_reopen_session_on_401(legacy_client):
    legacy_client.session.post.side_effect = _legacy_login(legacy_client.session)
    legacy_client.session.request.side_effect = [
        make_response(401),
        make_response(200),
    ]

    response = legacy_client.request("GET", "/status")

    assert response.status_code == 200
    assert legacy_client.session.post.call_count == 2
    args, kwargs = legacy_client.session.request.call_args
    assert args == ("GET", "https://zsapi.zscalertwo.net/api/v1/status")
    assert "Authorization" not in kwargs["headers"]
