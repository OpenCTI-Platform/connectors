"""Virustotal client unittest."""

import unittest

from virustotal.client import VirusTotalClient


class VirusTotalClientTest(unittest.TestCase):
    def test_base64_encode_no_padding(self):
        self.assertEqual(
            VirusTotalClient.base64_encode_no_padding("http://myetherevvalliet.com/"),
            "aHR0cDovL215ZXRoZXJldnZhbGxpZXQuY29tLw",
        )

    def test_x_tool_header_set(self):
        from unittest.mock import MagicMock

        helper = MagicMock()
        helper.connector_id = "test-connector-uuid"
        client = VirusTotalClient(helper, "https://www.virustotal.com", "fake-api-key")
        self.assertIn("x-tool", client.headers)
        self.assertIn("test-connector-uuid", client.headers["x-tool"])
