# -*- coding: utf-8 -*-
"""Unit tests for the STIX converter (Note building, helpers).

Skipped when connectors_sdk / pycti are not installed, mirroring the test
convention of sibling connectors.
"""

import importlib.util
import json
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

SDK_AVAILABLE = (
    importlib.util.find_spec("connectors_sdk") is not None
    and importlib.util.find_spec("pycti") is not None
)

if SDK_AVAILABLE:
    from connectors_sdk.models import TLPMarking
    from xposedornot.client_api import _normalise_free
    from xposedornot.converter_to_stix import ConverterToStix, _md_cell

sdk_required = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="connectors_sdk / pycti not installed in this environment",
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SOURCE_ID = "email-addr--3f8a3b62-32e9-5efc-8e18-4b34ba6c4f36"


def _result():
    with open(
        os.path.join(FIXTURES, "breach_analytics.json"), "r", encoding="utf-8"
    ) as fh:
        return _normalise_free(json.load(fh))


@sdk_required
def test_note_contains_breach_table_and_summary():
    converter = ConverterToStix(
        ConverterToStix.make_author(), TLPMarking(level="amber")
    )
    note = converter.build_note(SOURCE_ID, _result())
    stix = note.to_stix2_object()
    content = stix["content"]
    assert "**Breaches found:** 2" in content
    assert "**First exposure:** 2013 — **Latest:** 2026" in content
    assert "**Overall risk:** Critical (100/100)" in content
    assert "plaintext" in content.lower()
    assert "| Sysco | 2026 | 2,699,339 | sysco.com |" in content
    assert SOURCE_ID in stix["object_refs"]
    assert "XposedOrNot — exposed in 2 data breach(es)" == stix["abstract"]


@sdk_required
def test_note_is_deterministic_across_runs():
    converter = ConverterToStix(
        ConverterToStix.make_author(), TLPMarking(level="amber")
    )
    id_one = converter.build_note(SOURCE_ID, _result()).to_stix2_object()["id"]
    id_two = converter.build_note(SOURCE_ID, _result()).to_stix2_object()["id"]
    assert id_one == id_two


@sdk_required
def test_note_id_is_unique_per_source_observable():
    # Two different observables with an identical breach set must NOT share a
    # Note id (the SDK derives the id from content/abstract, not object_refs).
    converter = ConverterToStix(
        ConverterToStix.make_author(), TLPMarking(level="amber")
    )
    other_id = "email-addr--22222222-2222-4222-8222-222222222222"
    id_a = converter.build_note(SOURCE_ID, _result()).to_stix2_object()["id"]
    id_b = converter.build_note(other_id, _result()).to_stix2_object()["id"]
    assert id_a != id_b


@sdk_required
def test_helpers():
    result = _result()
    assert ConverterToStix.years(result["breaches"]) == (2013, 2026)
    assert ConverterToStix.has_plaintext_exposure(result["breaches"]) is True
    assert _md_cell("a|b\nc") == "a\\|b c"
    assert _md_cell(None) == "—"
