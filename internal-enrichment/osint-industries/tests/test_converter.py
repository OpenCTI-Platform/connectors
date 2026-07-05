# -*- coding: utf-8 -*-
"""Tests d'integration du converter sur la fixture de reponse complete.

Requierent connectors_sdk + pycti installes. S'executent chez toi dans le
venv du connecteur ; sont automatiquement skippes la ou le SDK est absent.
"""

import importlib.util
import json
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

# Detect whether the SDK is installed, without importing it (so no unused
# import). Only a missing SDK skips the tests; a genuine import bug in the
# converter still fails loudly.
SDK_AVAILABLE = (
    importlib.util.find_spec("connectors_sdk") is not None
    and importlib.util.find_spec("pycti") is not None
)

if SDK_AVAILABLE:
    from connectors_sdk.models import TLPMarking
    from osint_industries.converter_to_stix import ConverterToStix

sdk_required = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="connectors_sdk / pycti non installes dans cet environnement",
)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_response.json")


@pytest.fixture
def payload():
    with open(FIXTURE, "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def converter():
    author = ConverterToStix.make_author()
    tlp = TLPMarking(level="amber+strict")
    return ConverterToStix(author=author, tlp=tlp)


class FakeObservable(dict):
    """Observable source minimal (un Email-Addr enrichi)."""

    def __init__(self):
        super().__init__(
            standard_id="email-addr--4de9b600-36c5-4d6f-80bd-f11430a19a0c",
            entity_type="Email-Addr",
            observable_value="test@example.com",
            value="test@example.com",
        )


def _collect_labels(objs):
    """Rassemble les labels de tous les objets, en lisant aussi bien `labels`
    (SDOs) and `x_opencti_labels` (STIX observables, where the SDK stores labels)."""
    found = set()
    for o in objs:
        for attr in ("labels", "x_opencti_labels"):
            vals = getattr(o, attr, None)
            if vals is None and isinstance(o, dict):
                vals = o.get(attr)
            for lab in vals or []:
                found.add(lab)
    return found


@sdk_required
def test_process_returns_objects(converter, payload):
    objs = converter.process(FakeObservable(), payload)
    assert len(objs) > 0


@sdk_required
def test_not_found_module_is_skipped(converter, payload):
    """Le module 'deadmodule' (status not_found) ne doit produire aucun label."""
    objs = converter.process(FakeObservable(), payload)
    all_labels = _collect_labels(objs)
    assert "deadmodule" not in all_labels


@sdk_required
def test_user_accounts_created_per_module(converter, payload):
    """The module is carried by the object labels (not by account_type,
    que la plateforme vide pour les valeurs custom)."""
    objs = converter.process(FakeObservable(), payload)
    all_labels = _collect_labels(objs)
    # okru, qq, hibp, emailchecker, github attendus dans les labels
    for expected in ("okru", "qq", "github", "emailchecker"):
        assert expected in all_labels


@sdk_required
def test_email_observable_extracted(converter, payload):
    objs = converter.process(FakeObservable(), payload)
    values = {getattr(o, "value", None) for o in objs}
    assert "victim@qq.com" in values


@sdk_required
def test_breach_note_created(converter, payload):
    objs = converter.process(FakeObservable(), payload)
    has_note = any(getattr(o, "content", None) for o in objs)
    assert has_note


class _Src(dict):
    """Parameterisable source observable (an Email-Addr)."""

    def __init__(self, value, std_id):
        super().__init__(
            standard_id=std_id,
            entity_type="Email-Addr",
            observable_value=value,
            value=value,
        )


@sdk_required
def test_no_username_accounts_are_unique_per_email(converter, payload):
    """Two distinct source emails enriched on the SAME platform without a handle
    (e.g. emailchecker) must produce two user-accounts with different STIX ids
    -> no unintended merge on the platform side."""
    src1 = _Src(
        "email1@example.com", "email-addr--11111111-1111-4111-8111-111111111111"
    )
    src2 = _Src(
        "email2@example.com", "email-addr--22222222-2222-4222-8222-222222222222"
    )

    def login_for(objs, module):
        out = set()
        for o in objs:
            labels = getattr(o, "labels", None) or getattr(o, "x_opencti_labels", None)
            if labels and module in labels and getattr(o, "account_login", None):
                out.add(o.account_login)
        return out

    objs1 = converter.process(src1, payload)
    objs2 = converter.process(src2, payload)
    logins1 = login_for(objs1, "emailchecker")
    logins2 = login_for(objs2, "emailchecker")
    # an emailchecker login is present in each run, and they differ
    assert logins1 and logins2
    assert logins1.isdisjoint(logins2)
    # and each encodes "email [platform]" (uniqueness by email+platform)
    assert any(lg.endswith("[emailchecker]") for lg in logins1)


@sdk_required
def test_display_name_uses_bracket_platform(converter, payload):
    """display_name au format '<pseudo ou email> [plateforme]'."""
    objs = converter.process(FakeObservable(), payload)
    names = [getattr(o, "display_name", None) for o in objs]
    names = [n for n in names if n]
    assert any(n.endswith("[github]") for n in names)
