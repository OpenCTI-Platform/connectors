import gzip
from unittest.mock import MagicMock, patch

import pytest

from rst_threat_feed_client.api_client import ThreatFeedClient, _sanitize_output_path


def _client(**overrides):
    conf = {
        "baseurl": "https://api.rstcloud.net/v1",
        "apikey": "key",
        "proxy": "",
        "latest": "day",
        "retry": 0,
    }
    conf.update(overrides)
    return ThreatFeedClient(conf)


def test_client_without_explicit_proxy_does_not_override_env_proxies():
    client = _client()
    assert client._session.proxies == {}


def test_client_with_explicit_proxy_sets_session_proxies():
    client = _client(proxy="http://corp-proxy:8080")
    assert client._session.proxies == {
        "http": "http://corp-proxy:8080",
        "https": "http://corp-proxy:8080",
    }


def test_get_feed_does_not_pass_proxies_kwarg(tmp_path):
    client = _client()
    fake_response = MagicMock()
    fake_response.status_code = 500
    fake_response.text = "error"
    fake_response.json.side_effect = ValueError("not json")

    with patch.object(client._session, "get", return_value=fake_response) as mock_get:
        client.get_feed("domain", path=str(tmp_path / "out.json"))

    assert mock_get.call_count == 1
    _, kwargs = mock_get.call_args
    assert "proxies" not in kwargs


def test_get_feed_writes_decompressed_body(tmp_path):
    client = _client()
    body = b'{"ioc":"example.com"}\n'
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.content = gzip.compress(body)

    out = tmp_path / "threatfeed_domain_latest.json"
    with patch.object(client._session, "get", return_value=fake_response):
        result = client.get_feed("domain", path=str(out))

    assert result == {"status": "ok", "message": str(out)}
    assert out.read_bytes() == body


def test_get_feed_default_filename_has_no_gz_suffix():
    client = _client()
    fake_response = MagicMock()
    fake_response.status_code = 500
    fake_response.text = "error"
    fake_response.json.side_effect = ValueError("not json")

    with patch.object(client._session, "get", return_value=fake_response):
        with patch(
            "rst_threat_feed_client.api_client._sanitize_output_path",
            side_effect=lambda path: path,
        ) as sanitizer:
            result = client.get_feed("domain")

    assert result["status"] == "error"
    sanitizer.assert_called_once_with("threatfeed_domain_latest.json")


def test_get_feed_returns_json_error_payload(tmp_path):
    client = _client()
    fake_response = MagicMock()
    fake_response.status_code = 403
    fake_response.json.return_value = {"status": "error", "message": "forbidden"}

    with patch.object(client._session, "get", return_value=fake_response):
        result = client.get_feed("domain", path=str(tmp_path / "out.json"))

    assert result == {"status": "error", "message": "forbidden"}


def test_get_feed_rejects_unsupported_latest_window():
    client = _client(latest="week")
    result = client.get_feed("domain")
    assert result["status"] == "error"
    assert "Unsupported latest window" in result["message"]


def test_get_feed_rejects_path_traversal():
    client = _client()
    with pytest.raises(ValueError, match="Invalid file path"):
        client.get_feed("domain", path="../secret.json")


def test_sanitize_output_path_rejects_traversal():
    with pytest.raises(ValueError, match="Invalid file path"):
        _sanitize_output_path("../etc/passwd")
    with pytest.raises(ValueError, match="Invalid file path"):
        _sanitize_output_path("feeds/../../secret")


def test_sanitize_output_path_allows_safe_names(tmp_path):
    safe = str(tmp_path / "out.json")
    assert _sanitize_output_path(safe) == safe
    assert _sanitize_output_path("threatfeed_domain_latest.json") == (
        "threatfeed_domain_latest.json"
    )
