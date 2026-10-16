from unittest.mock import Mock

import pytest
import requests
from stream_connector.client import ZscalerAuthenticationError, ZscalerClient
from zscaler_responses import make_response

TOKEN = {"access_token": "token-1", "token_type": "Bearer", "expires_in": 3600}


def test_base_url_should_target_production_cloud_by_default(client):
    assert client.base_url == "https://api.zsapi.net/zia/api/v1"
    assert client.token_url == "https://acme.zslogin.net/oauth2/v1/token"


def test_base_url_should_include_cloud_when_set():
    client = ZscalerClient(
        logger=Mock(),
        client_id="client-id",
        client_secret="client-secret",
        vanity_domain="acme",
        cloud="beta",
    )

    assert client.base_url == "https://api.beta.zsapi.net/zia/api/v1"


def test_authenticate_should_request_token_with_client_credentials(client):
    client.session.post.return_value = make_response(200, TOKEN)

    client.authenticate()

    _, kwargs = client.session.post.call_args
    assert client.session.post.call_args.args[0] == client.token_url
    assert kwargs["data"] == {
        "grant_type": "client_credentials",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "audience": "https://api.zscaler.com",
    }
    assert client._access_token == "token-1"


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

    client._token_expires_at = 0  # token expired
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


def test_request_should_wait_for_rate_limit_reset_on_429(client, monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("stream_connector.client.time.sleep", sleep)
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.side_effect = [
        make_response(429, headers={"x-ratelimit-reset": "7"}),
        make_response(200),
    ]

    response = client.request("GET", "/status")

    assert response.status_code == 200
    sleep.assert_called_once_with(7)


def test_request_should_return_last_429_after_max_retries(client, monkeypatch):
    monkeypatch.setattr("stream_connector.client.time.sleep", Mock())
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.return_value = make_response(429)

    response = client.request("GET", "/status")

    assert response.status_code == 429
    assert client.session.request.call_count == client.max_retries


def test_request_should_return_none_when_authentication_fails(client):
    client.session.post.return_value = make_response(401)

    assert client.request("GET", "/status") is None
    client.session.request.assert_not_called()


def test_request_should_return_none_on_network_error(client):
    client.session.post.return_value = make_response(200, TOKEN)
    client.session.request.side_effect = requests.ConnectionError("boom")

    assert client.request("GET", "/status") is None
