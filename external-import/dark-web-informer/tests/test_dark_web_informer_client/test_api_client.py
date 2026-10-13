"""Tests for the Dark Web Informer API client (no network)."""

import re
from unittest.mock import MagicMock

import pytest
import requests
from dark_web_informer_client.api_client import DarkWebInformerClient


def _response(status_code=200, json_data=None, headers=None):
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.headers = headers or {}
    response.json.return_value = json_data if json_data is not None else {}
    response.raise_for_status.return_value = None
    return response


@pytest.fixture
def client(helper):
    client = DarkWebInformerClient(
        helper=helper,
        base_url="https://api.darkwebinformer.com/",
        api_key="test-key",
    )
    client.session = MagicMock(spec=requests.Session)
    return client


def test_nonce_format():
    nonce = DarkWebInformerClient._build_nonce()
    assert re.fullmatch(r"\d{10}:[A-Za-z0-9_-]{6,}", nonce)


def test_nonce_is_single_use():
    assert DarkWebInformerClient._build_nonce() != DarkWebInformerClient._build_nonce()


def test_base_url_trailing_slash_is_stripped(client):
    assert client.base_url == "https://api.darkwebinformer.com"


def test_headers_carry_api_key_and_nonce(client):
    headers = client._headers()

    assert headers["X-API-Key"] == "test-key"
    assert headers["Accept"] == "application/json"
    assert re.fullmatch(r"\d{10}:[A-Za-z0-9_-]{6,}", headers["X-Nonce"])


def test_get_builds_url_and_returns_json(client):
    client.session.get.return_value = _response(json_data={"type": "bundle"})

    assert client._get("/api/stix.json") == {"type": "bundle"}

    url = client.session.get.call_args.args[0]
    assert url == "https://api.darkwebinformer.com/api/stix.json"
    assert client.session.get.call_args.kwargs["timeout"] == 300


def test_get_raises_on_http_error(client):
    response = _response(status_code=500)
    response.raise_for_status.side_effect = requests.HTTPError("boom")
    client.session.get.return_value = response

    with pytest.raises(requests.HTTPError):
        client._get("/api/stix.json")


def test_get_retries_after_429(client, monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", slept.append)
    client.session.get.side_effect = [
        _response(status_code=429, headers={"Retry-After": "3"}),
        _response(json_data={"type": "bundle"}),
    ]

    assert client._get("/api/stix.json") == {"type": "bundle"}
    assert slept == [4]  # Retry-After + 1
    assert client.helper.connector_logger.warning.called


def test_get_falls_back_to_default_backoff(client, monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", slept.append)
    client.session.get.side_effect = [
        _response(status_code=429, headers={"Retry-After": "not-a-number"}),
        _response(json_data={}),
    ]

    client._get("/api/stix.json")

    assert slept == [61]  # _DEFAULT_BACKOFF_SECONDS + 1


def test_get_uses_ratelimit_reset_when_no_retry_after(client, monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", slept.append)
    client.session.get.side_effect = [
        _response(status_code=429, headers={"RateLimit-Reset": "5"}),
        _response(json_data={}),
    ]

    client._get("/api/stix.json")

    assert slept == [6]


def test_get_gives_up_after_max_retries(client, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    response = _response(status_code=429, headers={"Retry-After": "1"})
    response.raise_for_status.side_effect = requests.HTTPError("429")
    client.session.get.return_value = response

    with pytest.raises(requests.HTTPError):
        client._get("/api/stix.json")

    assert client.session.get.call_count == 6  # initial call + _MAX_RETRIES


@pytest.mark.parametrize(
    "source,expected_path",
    [
        ("all", "/api/stix/export.json"),
        ("feed", "/api/stix/export_feed.json"),
        ("ransomware", "/api/stix/export_ransomware.json"),
        ("iocs", "/api/stix/export_iocs.json"),
    ],
)
def test_get_stix_bundle_endpoints(client, source, expected_path):
    client.session.get.return_value = _response(json_data={"type": "bundle"})

    assert client.get_stix_bundle(source) == {"type": "bundle"}
    assert client.session.get.call_args.args[0].endswith(expected_path)


def test_get_stix_bundle_rejects_unknown_source(client):
    with pytest.raises(KeyError):
        client.get_stix_bundle("nope")


def test_get_stix_preview_passes_source_and_limit(client):
    client.session.get.return_value = _response(json_data={"type": "bundle"})

    client.get_stix_preview(source="feed", limit=10)

    assert client.session.get.call_args.args[0].endswith("/api/stix.json")
    assert client.session.get.call_args.kwargs["params"] == {
        "source": "feed",
        "limit": 10,
    }
