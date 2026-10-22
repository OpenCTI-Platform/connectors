from unittest.mock import MagicMock

import pytest
from connectors_sdk import ApiForbiddenError, ApiRateLimitError
from pydantic import ValidationError
from spur_client import IPContext, SpurClient, TagMetadata, api_client


def _response(status_code: int, json_body: dict | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.ok = status_code < 400
    response.headers = {"Content-Type": "application/json"}
    response.json.return_value = json_body or {}
    response.text = "body"
    return response


@pytest.fixture
def client(monkeypatch) -> SpurClient:
    client = SpurClient(base_url="https://api.spur.us/", api_key="secret")
    monkeypatch.setattr(client, "_raw_request", MagicMock())
    return client


def test_client_should_authenticate_with_the_token_header():
    client = SpurClient(base_url="https://api.spur.us", api_key="secret")

    assert client.session_headers == {"Token": "secret"}


def test_get_ip_context_should_query_the_context_endpoint(client):
    # Given Spur knows the IP
    client._raw_request.return_value = _response(200, {"ip": "1.2.3.4"})

    # When fetching its context
    ip_context = client.get_ip_context("1.2.3.4")

    # Then the context endpoint is called and its body returned
    client._raw_request.assert_called_once_with(
        "GET", "/v2/context/1.2.3.4", params=None
    )
    assert ip_context == IPContext(ip="1.2.3.4")


def test_get_ip_context_should_raise_when_the_response_is_invalid(client):
    # Given Spur answers with a body that is not an IP context
    client._raw_request.return_value = _response(200, {"ip": "not-an-ip"})

    # When / Then the response is rejected
    with pytest.raises(ValidationError):
        client.get_ip_context("1.2.3.4")


def test_get_ip_context_should_return_none_when_spur_rejects_the_ip(client):
    # Given Spur rejects the IP (private or reserved)
    client._raw_request.return_value = _response(400)

    # When / Then no context is returned
    assert client.get_ip_context("10.0.0.1") is None


@pytest.mark.parametrize(
    "status_code, error_class",
    [(403, ApiForbiddenError), (429, ApiRateLimitError)],
)
def test_get_ip_context_should_raise_on_other_errors(client, status_code, error_class):
    # Given Spur answers with an error
    client._raw_request.return_value = _response(status_code)

    # When / Then the error is raised
    with pytest.raises(error_class):
        client.get_ip_context("1.2.3.4")


def test_get_tag_metadata_should_query_the_tag_metadata_endpoint(client):
    # Given Spur knows the tag
    client._raw_request.return_value = _response(
        200, {"tag": "PROTON_VPN", "name": "Proton VPN", "isNoLog": True}
    )

    # When fetching its metadata
    metadata = client.get_tag_metadata("PROTON_VPN")

    # Then the tag metadata endpoint is called and its body returned
    client._raw_request.assert_called_once_with(
        "GET", "/v2/metadata/tags/PROTON_VPN", params=None
    )
    assert metadata == TagMetadata(tag="PROTON_VPN", name="Proton VPN", is_no_log=True)


def test_get_tag_metadata_should_return_none_for_an_unknown_tag(client):
    # Given Spur does not know the tag
    client._raw_request.return_value = _response(404)

    # When / Then no metadata is returned
    assert client.get_tag_metadata("UNKNOWN_TAG") is None


def test_get_tag_metadata_should_raise_on_other_errors(client):
    # Given Spur answers with an error
    client._raw_request.return_value = _response(429)

    # When / Then the error is raised
    with pytest.raises(ApiRateLimitError):
        client.get_tag_metadata("PROTON_VPN")


@pytest.mark.parametrize("status_code", [200, 404])
def test_get_tag_metadata_should_cache_the_result(client, status_code):
    # Given a first call for the tag, known or unknown
    client._raw_request.return_value = _response(status_code, {"tag": "PROTON_VPN"})
    first = client.get_tag_metadata("PROTON_VPN")

    # When fetching it again
    second = client.get_tag_metadata("PROTON_VPN")

    # Then Spur is called only once
    assert client._raw_request.call_count == 1
    assert second == first


def test_get_tag_metadata_should_refresh_an_expired_cache(client, monkeypatch):
    # Given metadata cached longer ago than the cache lifetime
    now = 1000.0
    monkeypatch.setattr(api_client.time, "monotonic", lambda: now)
    client._raw_request.return_value = _response(200, {"tag": "PROTON_VPN"})
    client.get_tag_metadata("PROTON_VPN")
    now += api_client.TAG_METADATA_CACHE_TTL_SECONDS

    # When fetching it again
    client.get_tag_metadata("PROTON_VPN")

    # Then Spur is called again
    assert client._raw_request.call_count == 2
