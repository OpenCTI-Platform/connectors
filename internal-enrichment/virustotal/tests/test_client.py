# -*- coding: utf-8 -*-
"""Virustotal client unittest."""
import unittest

from src.virustotal.client import VirusTotalClient


class VirusTotalClientTest(unittest.TestCase):
    def test_base64_encode_no_padding(self):
        self.assertEqual(
            VirusTotalClient.base64_encode_no_padding("http://myetherevvalliet.com/"),
            "aHR0cDovL215ZXRoZXJldnZhbGxpZXQuY29tLw",
        )
