"""Unit tests for shared utilities used by the Metras Enrichment connector."""

from connector.utils import is_valid_ipv4, is_valid_url, refang


def test_refang_for_enrichment():
    assert refang("8[.]8[.]8[.]8") == "8.8.8.8"
    assert refang("hxxp://bad[.]example") == "http://bad.example"


def test_validators():
    assert is_valid_ipv4("10.200.0.214")
    assert is_valid_url("https://dashboard.metras.sa/")
