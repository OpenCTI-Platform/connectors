from unittest.mock import MagicMock, patch

import pytest

from rst_threat_feed_client.api_client import ThreatFeedClient, _sanitize_output_path


def test_client_without_explicit_proxy_does_not_override_env_proxies():
    client = ThreatFeedClient(
        {
            "baseurl": "https://api.rstcloud.net/v1",
            "apikey": "key",
            "proxy": "",
        }
    )

    assert client._session.proxies == {}


def test_client_with_explicit_proxy_sets_session_proxies():
    client = ThreatFeedClient(
        {
            "baseurl": "https://api.rstcloud.net/v1",
            "apikey": "key",
            "proxy": "http://corp-proxy:8080",
        }
    )

    assert client._session.proxies == {
        "http": "http://corp-proxy:8080",
        "https": "http://corp-proxy:8080",
    }


def test_get_feed_does_not_pass_proxies_kwarg(tmp_path):
    client = ThreatFeedClient(
        {
            "baseurl": "https://api.rstcloud.net/v1",
            "apikey": "key",
            "proxy": "",
            "latest": "day",
            "retry": 0,
        }
    )
    fake_response = MagicMock()
    fake_response.status_code = 500
    fake_response.text = "error"
    fake_response.json.side_effect = ValueError("not json")

    with patch.object(client._session, "get", return_value=fake_response) as mock_get:
        client.get_feed("domain", path=str(tmp_path / "out.json"))

    assert mock_get.call_count == 1
    _, kwargs = mock_get.call_args
    assert "proxies" not in kwargs


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
