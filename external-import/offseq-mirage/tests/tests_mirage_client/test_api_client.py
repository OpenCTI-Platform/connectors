from unittest.mock import MagicMock

from mirage_client import MirageFeedClient

URL = "https://feeds.offseq.com/mirage-feed/latest/stix/mirage.json"


def test_get_bundle_requests_the_feed_url():
    client = MirageFeedClient(URL)
    client._request = MagicMock(return_value={"type": "bundle", "id": "bundle--x"})
    assert client.get_bundle()["id"] == "bundle--x"
    client._request.assert_called_once_with("GET", URL, params=None)


def test_headers_identify_the_connector():
    headers = MirageFeedClient(URL).session_headers
    assert headers["User-Agent"].startswith("opencti-offseq-mirage-connector/")
