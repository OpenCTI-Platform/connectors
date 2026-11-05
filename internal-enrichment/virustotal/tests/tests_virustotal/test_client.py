"""Virustotal client unittest."""

import unittest
from unittest.mock import MagicMock, patch

from virustotal.client import VirusTotalClient


def _make_client() -> VirusTotalClient:
    helper = MagicMock()
    helper.connector_id = "test-connector-uuid"
    return VirusTotalClient(helper, "https://www.virustotal.com/api/v3", "fake-api-key")


class VirusTotalClientTest(unittest.TestCase):
    def test_base64_encode_no_padding(self):
        self.assertEqual(
            VirusTotalClient.base64_encode_no_padding("http://myetherevvalliet.com/"),
            "aHR0cDovL215ZXRoZXJldnZhbGxpZXQuY29tLw",
        )

    def test_x_tool_header_set(self):
        helper = MagicMock()
        helper.connector_id = "test-connector-uuid"
        client = VirusTotalClient(helper, "https://www.virustotal.com", "fake-api-key")
        self.assertIn("x-tool", client.headers)
        self.assertIn("test-connector-uuid", client.headers["x-tool"])

    def test_get_url_related_objects_extra_query_appended(self):
        client = _make_client()
        with patch.object(client, "_query", return_value={"data": []}) as mock_query:
            client.get_url_related_objects(
                "http://example.com", "malware_families", extra_query="limit=5"
            )
        called_url = mock_query.call_args[0][0]
        self.assertTrue(called_url.endswith("/malware_families?limit=5"))

    def test_get_url_related_objects_no_extra_query_unchanged(self):
        client = _make_client()
        with patch.object(client, "_query", return_value={"data": []}) as mock_query:
            client.get_url_related_objects("http://example.com", "malware_families")
        called_url = mock_query.call_args[0][0]
        self.assertTrue(called_url.endswith("/malware_families"))
        self.assertNotIn("?", called_url)

    def test_get_gti_relationship_ip_addresses_single_page(self):
        client = _make_client()
        page = {"data": [{"id": "a"}, {"id": "b"}], "links": {}}
        with patch.object(client, "_query", return_value=page) as mock_query:
            result = client.get_gti_relationship(
                "ip_addresses", "1.2.3.4", "malware_families", 10
            )
        mock_query.assert_called_once()
        called_url = mock_query.call_args[0][0]
        self.assertEqual(
            called_url,
            "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/malware_families?limit=10",
        )
        self.assertEqual(len(result["data"]), 2)

    def test_get_gti_relationship_urls_delegates_with_extra_query(self):
        client = _make_client()
        with patch.object(
            client, "get_url_related_objects", return_value={"data": [{"id": "a"}]}
        ) as mock_related:
            client.get_gti_relationship("urls", "http://example.com", "reports", 7)
        mock_related.assert_called_once_with(
            "http://example.com", "reports", extra_query="limit=7"
        )

    def test_get_gti_relationship_limit_zero_skips_call(self):
        client = _make_client()
        with patch.object(client, "_query") as mock_query:
            result = client.get_gti_relationship(
                "ip_addresses", "1.2.3.4", "malware_families", 0
            )
        mock_query.assert_not_called()
        self.assertEqual(result, {"data": []})

    def test_get_gti_relationship_follows_pagination_up_to_limit(self):
        client = _make_client()
        page_1 = {
            "data": [{"id": "a"}, {"id": "b"}],
            "links": {"next": "https://www.virustotal.com/api/v3/next-page"},
        }
        page_2 = {"data": [{"id": "c"}, {"id": "d"}], "links": {}}
        with patch.object(client, "_query", side_effect=[page_1, page_2]) as mock_query:
            result = client.get_gti_relationship(
                "ip_addresses", "1.2.3.4", "malware_families", 3
            )
        self.assertEqual(mock_query.call_count, 2)
        # Truncated to the requested limit even though 4 items were fetched.
        self.assertEqual(len(result["data"]), 3)
        self.assertEqual([d["id"] for d in result["data"]], ["a", "b", "c"])

    def test_get_gti_relationship_stops_when_no_next_link(self):
        client = _make_client()
        page = {"data": [{"id": "a"}], "links": {}}
        with patch.object(client, "_query", return_value=page) as mock_query:
            result = client.get_gti_relationship(
                "ip_addresses", "1.2.3.4", "malware_families", 40
            )
        mock_query.assert_called_once()
        self.assertEqual(len(result["data"]), 1)

    def test_get_gti_relationship_returns_none_on_query_failure(self):
        client = _make_client()
        with patch.object(client, "_query", return_value=None):
            result = client.get_gti_relationship(
                "ip_addresses", "1.2.3.4", "malware_families", 10
            )
        self.assertIsNone(result)
