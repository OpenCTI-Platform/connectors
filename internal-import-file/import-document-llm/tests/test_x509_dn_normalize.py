"""
Unit tests for X.509 Distinguished Name (DN) normalization.

These tests verify that X.509 subject/issuer strings are normalized consistently
regardless of formatting differences (e.g., spacing, slash vs. comma notation,
alias attribute names, and case).
"""

import os
import sys

# Ensure repo-local imports work when running via pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from reportimporter.regex_scanner import normalize_stix_value


def _n(stix_type: str, value: str) -> str:
    """Helper to normalize X.509 DNs using the shared normalizer."""
    return normalize_stix_value(stix_type, value)


# --- Tests -------------------------------------------------------------------


def test_dn_normalization_commas_and_spaces():
    """DNs with extra spaces and commas should normalize identically."""
    a = "CN= Example Corp , O= Org , C= US"
    b = "C=US,O=Org,CN=Example Corp"
    na = _n("X509-Certificate.issuer", a)
    nb = _n("X509-Certificate.issuer", b)
    assert na == nb
    assert na.startswith("C=US") and "CN=Example Corp" in na


def test_dn_normalization_aliases_and_case():
    """Alias attribute names and differing case should normalize equivalently."""
    a = "e=admin@example.com, cn=Alice, o=Org, c=US"
    b = "EMAILADDRESS=admin@example.com, CN=Alice, O=Org, C=US"
    na = _n("X509-Certificate.subject", a)
    nb = _n("X509-Certificate.subject", b)
    assert na == nb
    assert "EMAILADDRESS=admin@example.com" in na


def test_dn_normalization_slash_notation():
    """Slash-separated DNs should normalize equivalently to comma-separated form."""
    a = "/C=US/ST=CA/L=SF/O=Org/OU=Unit/CN=Alice"
    b = "CN=Alice, OU=Unit, O=Org, L=SF, ST=CA, C=US"
    na = _n("X509-Certificate.subject", a)
    nb = _n("X509-Certificate.subject", b)
    assert na == nb
