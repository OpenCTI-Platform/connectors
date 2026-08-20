# -*- coding: utf-8 -*-
"""Additional converter tests covering the observable branches (phone, wallet,
URL), payload normalization, breach notes and the HTML report attachment for
the different source-observable types.
"""

import importlib.util
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
    from osint_industries import converter_to_stix as mod
    from osint_industries.converter_to_stix import ConverterToStix

sdk_required = pytest.mark.skipif(
    not SDK_AVAILABLE,
    reason="connectors_sdk / pycti not installed in this environment",
)


def _converter():
    return ConverterToStix(
        author=ConverterToStix.make_author(), tlp=TLPMarking(level="amber+strict")
    )


def _src(entity_type, value, std_id):
    return {
        "standard_id": std_id,
        "entity_type": entity_type,
        "observable_value": value,
        "value": value,
    }


@sdk_required
def test_normalize_modules_variants():
    assert ConverterToStix._normalize_modules(None) == []
    assert ConverterToStix._normalize_modules("nope") == []
    assert ConverterToStix._normalize_modules([{"a": 1}, "skip"]) == [{"a": 1}]
    assert ConverterToStix._normalize_modules({"results": [{"m": 1}]}) == [{"m": 1}]
    # bare dict with no wrapper key is treated as a single module
    assert ConverterToStix._normalize_modules({"module": "x"}) == [{"module": "x"}]


@sdk_required
def test_phone_and_wallet_and_url_observables_created():
    payload = [
        {
            "module": "somesite",
            "status": "found",
            "spec_format": [
                {
                    "registered": {"value": True, "type": "bool"},
                    "username": {"value": "bob", "type": "str"},
                    "phone": {"value": "+33123456789", "type": "str"},
                    "wallet": {"value": "0xabc123", "type": "str"},
                    "profile_url": {"value": "https://somesite/bob", "type": "str"},
                }
            ],
        }
    ]
    objs = _converter().process(
        _src(
            "Email-Addr",
            "a@b.com",
            "email-addr--" + "1" * 8 + "-1111-4111-8111-" + "1" * 12,
        ),
        payload,
    )
    types = {getattr(o, "type", None) for o in objs}
    assert "phone-number" in types
    assert "cryptocurrency-wallet" in types
    assert "url" in types
    assert "relationship" in types


@sdk_required
def test_breach_module_produces_breach_note():
    payload = [
        {
            "module": "hibp",
            "status": "found",
            "spec_format": [
                {
                    "registered": {"value": True, "type": "bool"},
                    "breach": {"value": True, "type": "bool"},
                    "platform_variables": [
                        {"key": "title", "value": "LinkedIn (2012)", "type": "str"},
                        {
                            "key": "data_classes",
                            "value": "Emails, Passwords",
                            "type": "str",
                        },
                        {"key": "added_date", "value": "2016-05-21", "type": "str"},
                    ],
                }
            ],
        }
    ]
    objs = _converter().process(
        _src(
            "Email-Addr",
            "a@b.com",
            "email-addr--" + "2" * 8 + "-2222-4222-8222-" + "2" * 12,
        ),
        payload,
    )
    breach_notes = [
        o
        for o in objs
        if getattr(o, "type", None) == "note"
        and "breach" in (getattr(o, "abstract", "") or "").lower()
    ]
    assert breach_notes


@sdk_required
@pytest.mark.parametrize(
    "entity_type,value,std_id",
    [
        (
            "Email-Addr",
            "a@b.com",
            "email-addr--" + "3" * 8 + "-3333-4333-8333-" + "3" * 12,
        ),
        ("Url", "https://x.test", "url--" + "4" * 8 + "-4444-4444-8444-" + "4" * 12),
        (
            "User-Account",
            "handle",
            "user-account--" + "5" * 8 + "-5555-4555-8555-" + "5" * 12,
        ),
    ],
)
def test_report_attachment_for_source_types(entity_type, value, std_id):
    payload = [
        {
            "module": "github",
            "status": "found",
            "spec_format": [
                {
                    "registered": {"value": True, "type": "bool"},
                    "username": {"value": "bob", "type": "str"},
                    "id": {"value": "gh-1", "type": "str"},
                }
            ],
        }
    ]
    objs = _converter().process(_src(entity_type, value, std_id), payload)
    with_files = [o for o in objs if getattr(o, "x_opencti_files", None)]
    assert with_files, "expected the HTML report attached to an observable"


@sdk_required
def test_report_attachment_fallback_to_richest_account_for_phone():
    payload = [
        {
            "module": "github",
            "status": "found",
            "spec_format": [
                {
                    "registered": {"value": True, "type": "bool"},
                    "username": {"value": "bob", "type": "str"},
                    "id": {"value": "gh-1", "type": "str"},
                    "location": {"value": "Lyon", "type": "str"},
                }
            ],
        }
    ]
    # Phone-Number source has no SDK observable supporting associated_files,
    # so the report falls back to the richest discovered account.
    objs = _converter().process(
        _src(
            "Phone-Number",
            "+33100000000",
            "phone-number--" + "6" * 8 + "-6666-4666-8666-" + "6" * 12,
        ),
        payload,
    )
    with_files = [o for o in objs if getattr(o, "x_opencti_files", None)]
    assert with_files


@sdk_required
def test_process_with_object_source_observable():
    class _Obs:
        id = "email-addr--" + "7" * 8 + "-7777-4777-8777-" + "7" * 12
        value = "a@b.com"

    payload = [
        {
            "module": "github",
            "status": "found",
            "spec_format": [{"username": {"value": "bob", "type": "str"}}],
        }
    ]
    objs = _converter().process(_Obs(), payload)
    assert objs


@sdk_required
def test_empty_payload_yields_no_accounts_or_notes():
    objs = _converter().process(
        _src(
            "Email-Addr",
            "a@b.com",
            "email-addr--" + "8" * 8 + "-8888-4888-8888-" + "8" * 12,
        ),
        [],
    )
    types = {getattr(o, "type", None) for o in objs}
    # only the author identity and the TLP marking are emitted
    assert "user-account" not in types
    assert "note" not in types


@sdk_required
def test_stringify_handles_list_and_dict():
    assert mod.ConverterToStix._stringify(["a", {"k": "v"}]) == "a | k=v"
    assert mod.ConverterToStix._stringify({"a": 1}) == "a=1"
    assert mod.ConverterToStix._stringify("plain") == "plain"


@sdk_required
def test_md_cell_escapes_pipes_and_newlines():
    assert mod.ConverterToStix._md_cell("a|b\nc") == "a\\|b c"


@sdk_required
def test_parse_date_accepts_datetime_instance():
    import datetime

    dt = datetime.datetime(2020, 1, 2, 3, 4, 5)
    assert mod._parse_date(dt) is dt
    assert mod._parse_date("not-a-date") is None
