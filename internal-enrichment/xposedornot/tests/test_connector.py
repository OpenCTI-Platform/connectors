# -*- coding: utf-8 -*-
"""Unit tests for connector-level helpers (validation, TLP extraction).

These test the pure functions that gate enrichment; the full message flow
requires a platform and is exercised in integration testing.
"""

import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

from xposedornot.connector import is_valid_email, observable_tlp  # noqa: E402


def test_email_validation():
    assert is_valid_email("user@example.com")
    assert is_valid_email("user+tag@sub.example.co.uk")
    assert not is_valid_email("not-an-email")
    assert not is_valid_email("")
    assert not is_valid_email("a@b")  # no TLD dot
    assert not is_valid_email("a" * 250 + "@example.com")  # too long


def test_observable_tlp_extraction():
    observable = {
        "objectMarking": [
            {"definition_type": "statement", "definition": "custom"},
            {"definition_type": "TLP", "definition": "TLP:AMBER"},
        ]
    }
    assert observable_tlp(observable) == "TLP:AMBER"
    assert observable_tlp({"objectMarking": []}) is None
    assert observable_tlp({}) is None
