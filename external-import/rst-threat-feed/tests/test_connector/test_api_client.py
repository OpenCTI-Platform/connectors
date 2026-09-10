from unittest.mock import MagicMock, patch

from rst_threat_feed_client.api_client import ThreatFeedClient


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
        client.get_feed("domain", path=str(tmp_path / "out.json.gz"))

    assert mock_get.call_count == 1
    _, kwargs = mock_get.call_args
    assert "proxies" not in kwargs
