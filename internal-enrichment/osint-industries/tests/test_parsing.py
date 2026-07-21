# -*- coding: utf-8 -*-
"""Tests des helpers de parsing du spec_format.

Ces tests n'ont PAS besoin du connectors_sdk ni de pycti : ils ciblent
les fonctions pures de converter_to_stix (parsing/aplatissement), qui sont
la partie la plus susceptible de casser quand la structure de l'API evolue.
"""

import importlib.util
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

converter_mod = None
# Detect whether the SDK is installed, without importing it (so no unused
# import). Only a missing SDK skips the tests; the converter import below
# stays outside this guard so any other import bug (report_html path, syntax
# error...) fails loudly instead of silently turning into a "skipped".
SDK_AVAILABLE = (
    importlib.util.find_spec("connectors_sdk") is not None
    and importlib.util.find_spec("pycti") is not None
)

if SDK_AVAILABLE:
    from osint_industries import converter_to_stix as converter_mod


sdk_required = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="connectors_sdk / pycti non installes dans cet environnement",
)


# --------------------------------------------------------------------------
# Les helpers de parsing sont des fonctions pures : on les reimplemente-pas,
# on les importe quand le module a pu etre charge.
# --------------------------------------------------------------------------
@sdk_required
def test_flatten_top_level_and_platform_variables():
    spec = {
        "registered": {"proper_key": "Registered", "value": True, "type": "bool"},
        "username": {"proper_key": "Username", "value": "bob", "type": "str"},
        "platform_variables": [
            {"key": "uid", "proper_key": "Uid", "value": "42", "type": "int"},
        ],
    }
    flat = converter_mod._flatten_spec(spec)
    assert flat["username"] == "bob"
    assert flat["uid"] == "42"
    assert flat["registered"] is True


@sdk_required
def test_flatten_discards_placeholders_and_empties():
    spec = {
        "name": {"proper_key": "Name", "value": "XXXXXXX", "type": "str"},
        "bio": {"proper_key": "Bio", "value": "", "type": "str"},
        "id": {"proper_key": "Id", "value": "real-id", "type": "str"},
        "platform_variables": [
            {"key": "empty", "proper_key": "Empty", "value": None, "type": "null"},
        ],
    }
    flat = converter_mod._flatten_spec(spec)
    assert "name" not in flat  # placeholder XXXXXXX ecarte
    assert "bio" not in flat  # vide ecarte
    assert flat["id"] == "real-id"
    assert "empty" not in flat


@sdk_required
def test_join_name_from_first_last():
    flat = {"first_name": "Jean", "last_name": "Test"}
    assert converter_mod._person_name(flat) == "Jean Test"


@sdk_required
def test_join_name_prefers_full_name():
    flat = {"name": "Full Name", "first_name": "Jean", "last_name": "Test"}
    assert converter_mod._person_name(flat) == "Full Name"


@sdk_required
def test_first_returns_first_non_empty():
    d = {"a": None, "b": "", "c": "value"}
    assert converter_mod._first(d, "a", "b", "c") == "value"


@sdk_required
def test_parse_date_iso():
    dt = converter_mod._parse_date("2016-05-21")
    assert dt is not None
    assert dt.year == 2016 and dt.month == 5 and dt.day == 21


@sdk_required
def test_parse_date_placeholder_returns_none():
    assert converter_mod._parse_date("XXXXXXX") is None
