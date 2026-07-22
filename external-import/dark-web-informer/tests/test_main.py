"""Smoke tests for the API client (no network, no SDK required)."""

import re

from dark_web_informer_client.api_client import DarkWebInformerClient


def test_nonce_format():
    nonce = DarkWebInformerClient._build_nonce()
    assert re.fullmatch(r"\d{10}:[A-Za-z0-9_-]{6,}", nonce)
