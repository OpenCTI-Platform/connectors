# -*- coding: utf-8 -*-
"""Unit tests for the connector: settings, init, and the enrichment flow.

The runtime requirements are installed by tests/test-requirements.txt, so a
broken import fails the suite rather than skipping it.
"""

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
import stix2
from connectors_sdk.models import TLPMarking
from connectors_sdk.models.enums import TLPLevel
from connectors_sdk.settings.exceptions import ConfigValidationError
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import OpenCTIConnectorHelper
from src.xposedornot.connector import (
    TLP_RANK,
    MarkingResolutionError,
    XposedOrNotConnector,
    canonical_tlp,
    effective_tlp_level,
    is_marking_id,
    is_own_reference,
    is_playbook_run,
    is_valid_email,
    listed,
    marking_id,
    materialize_marking,
    refused_tlps,
    resolve_source_markings,
    source_tlp_levels,
    tlp_marking_value,
    unique_by_id,
    usable_score,
)
from src.xposedornot.converter_to_stix import ObservableNote
from src.xposedornot.settings import ConnectorSettings

from tests.conftest import make_helper


class StubConnectorSettings(ConnectorSettings):
    """ConnectorSettings with a fake but valid config dict for tests."""

    _api_key: Any = None
    _api_base_url: str = "https://api.xposedornot.com"
    _scope: str = "Email-Addr"
    _tlp_level: str = "amber"
    _max_tlp: str = "TLP:AMBER"
    _max_note_breaches: int = 50
    _connector_id: Any = "connector-id"

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict:
        xon = {
            "api_base_url": cls._api_base_url,
            "max_tlp": cls._max_tlp,
            "tlp_level": cls._tlp_level,
            "max_note_breaches": cls._max_note_breaches,
        }
        if cls._api_key:
            xon["api_key"] = cls._api_key
        connector = {
            "name": "XposedOrNot",
            "scope": cls._scope,
            "log_level": "error",
            "auto": False,
        }
        if cls._connector_id:
            connector["id"] = cls._connector_id
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": connector,
                "xposedornot": xon,
            }
        )


@pytest.fixture(autouse=True)
def _reset_stub_settings():
    """Stub settings are class attributes; reset them so tests cannot leak state."""
    StubConnectorSettings._api_key = None
    StubConnectorSettings._api_base_url = "https://api.xposedornot.com"
    StubConnectorSettings._connector_id = "connector-id"
    StubConnectorSettings._scope = "Email-Addr"
    StubConnectorSettings._tlp_level = "amber"
    StubConnectorSettings._max_note_breaches = 50
    StubConnectorSettings._max_tlp = "TLP:AMBER"

    yield


BREACHED = {
    "breaches": [
        {
            "name": "Sysco",
            "date": "2026",
            "records": 2699339,
            "domain": "sysco.com",
            "industry": "Food",
            "password_risk": "plaintextpassword",
            "verified": "Yes",
            "data_classes": ["Email addresses", "Names"],
        }
    ],
    "risk_label": "Critical",
    "risk_score": 100,
}

OBSERVABLE_ID = "email-addr--11111111-1111-4111-8111-111111111111"


def _make_connector(api_key=None, scope="Email-Addr"):
    StubConnectorSettings._scope = scope
    StubConnectorSettings._api_key = api_key
    settings = StubConnectorSettings()
    helper = make_helper()
    return XposedOrNotConnector(config=settings, helper=helper), helper


def _enrichment_data(email="test@example.com", tlp="TLP:AMBER", playbook=False):
    marking = [{"definition_type": "TLP", "definition": tlp}] if tlp else []
    entity = {
        "id": OBSERVABLE_ID,
        "labels": ["legacy-label"],
        "external_references": [
            {"source_name": "Legacy Tool", "url": "https://legacy.test"}
        ],
    }
    observable = {
        "entity_type": "Email-Addr",
        "observable_value": email,
        "objectMarking": marking,
        "created_at": "2024-05-01T10:00:00.000Z",
    }
    data = {
        "enrichment_entity": observable,
        "stix_entity": entity,
        "stix_objects": [entity],
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
    return data


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------
def test_email_validation():
    assert is_valid_email("user@example.com")
    assert is_valid_email("user+tag@sub.example.co.uk")
    assert not is_valid_email("not-an-email")
    assert not is_valid_email("")
    assert not is_valid_email("a@b")
    assert not is_valid_email(f"{'a' * 250}@example.com")


def test_observable_tlp_extraction():
    observable = {
        "objectMarking": [
            {"definition_type": "statement", "definition": "custom"},
            {"definition_type": "TLP", "definition": "TLP:AMBER"},
            {"definition_type": "TLP", "definition": "TLP:RED"},
        ]
    }
    assert source_tlp_levels(observable) == (["amber", "red"], [])
    assert source_tlp_levels({"objectMarking": []}) == ([], [])
    assert source_tlp_levels({}) == ([], [])
    assert refused_tlps(observable, "TLP:AMBER") == (["TLP:RED"], [])
    assert refused_tlps(observable, "TLP:RED") == ([], [])
    assert refused_tlps({}, "TLP:CLEAR") == ([], [])


# ---------------------------------------------------------------------------
# settings + init
# ---------------------------------------------------------------------------
def test_settings_instantiate_and_helper_config():
    settings = StubConnectorSettings()
    assert isinstance(settings, ConnectorSettings)
    assert isinstance(settings.to_helper_config(), dict)
    assert settings.xposedornot.max_tlp == "TLP:AMBER"
    assert settings.xposedornot.api_key is None


def test_settings_have_a_default_connector_id():
    StubConnectorSettings._connector_id = None
    settings = StubConnectorSettings()
    assert settings.connector.id == "c6b0f5f2-c47e-4d49-92a9-10371b40f5d8"
    assert settings.to_helper_config()["connector"]["id"] == settings.connector.id


def test_settings_reject_unsupported_scope_entries():
    StubConnectorSettings._scope = "Email-Addr,Domain-Name"
    with pytest.raises(ConfigValidationError) as raised:
        StubConnectorSettings()
    assert "Domain-Name" in str(raised.value.__cause__)


def test_connector_uses_the_configured_scope():
    connector, _ = _make_connector()
    assert connector.scopes == ["Email-Addr"]


def test_max_note_breaches_reaches_the_converter_and_rejects_negatives():
    connector, _ = _make_connector()
    assert connector.converter.max_table_rows == 50
    StubConnectorSettings._max_note_breaches = 5
    assert (
        XposedOrNotConnector(
            config=StubConnectorSettings(), helper=MagicMock()
        ).converter.max_table_rows
        == 5
    )
    StubConnectorSettings._max_note_breaches = -1
    with pytest.raises(ConfigValidationError):
        StubConnectorSettings()


RED_MARKING_DEF = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    "created": "2017-01-20T00:00:00.000Z",
    "definition_type": "tlp",
    "name": "TLP:RED",
    "definition": {"tlp": "red"},
}


def test_entity_reference_markings_gate_before_the_api_call():
    """A marking expressed only as object_marking_refs must gate too.

    Reading just objectMarking let a TLP:RED observable through an AMBER gate
    and the address reached the third-party API before anything refused it.
    """
    StubConnectorSettings._max_tlp = "TLP:AMBER"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(side_effect=AssertionError("API was called"))
    data = _enrichment_data()
    data["stix_entity"].pop("labels", None)
    data["stix_entity"].pop("external_references", None)
    data["stix_entity"]["object_marking_refs"] = [RED_MARKING_DEF["id"]]
    data["enrichment_entity"]["objectMarking"] = []
    data["stix_objects"].append(RED_MARKING_DEF)
    message = connector._process_message(data)
    assert "TLP:RED" in message and "higher than" in message
    connector.client.lookup.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_entity_reference_markings_raise_the_applied_level():
    StubConnectorSettings._max_tlp = "TLP:RED"
    StubConnectorSettings._tlp_level = "clear"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_entity"].pop("labels", None)
    data["stix_entity"].pop("external_references", None)
    data["stix_entity"]["object_marking_refs"] = [RED_MARKING_DEF["id"]]
    data["enrichment_entity"]["objectMarking"] = []
    data["stix_objects"].append(RED_MARKING_DEF)
    connector._process_message(data)
    sent = helper.stix2_create_bundle.call_args[0][0]
    names = {
        o.get("name")
        for o in sent
        if getattr(o, "get", dict().get)("type") == "marking-definition"
    }
    assert "TLP:RED" in names


def test_unreadable_tlp_markings_fail_closed():
    """A marking that declares TLP but carries no readable value must refuse.

    The unreadable half is asserted explicitly: `refused_tlps` returns a pair,
    and a bare `assert` on it is true whatever the function decided.
    """
    for value in (None, "", "   ", 7, object()):
        observable = {
            "objectMarking": [{"definition_type": "TLP", "definition": value}]
        }
        too_high, unreadable = refused_tlps(observable, "TLP:AMBER")
        assert (too_high, bool(unreadable)) == ([], True), repr(value)
    for observable in (
        {"objectMarking": [{"definition_type": "TLP"}]},
        {"objectMarking": [{"x_opencti_definition_type": "TLP"}]},
        {"objectMarking": [{"definition_type": "tlp", "definition": {"tlp": "mauve"}}]},
        {"objectMarking": ["TLP:RED"]},
        {"objectMarking": [None]},
    ):
        assert refused_tlps(observable, "TLP:AMBER")[1], observable


def test_sdk_statement_tlp_markings_are_read():
    """connectors-sdk spells CLEAR and AMBER+STRICT as custom statement markings.

    `definition_type` is `statement` there and the level lives in
    `x_opencti_definition*`, so a gate reading only `definition_type` saw no
    marking at all and let a TLP:AMBER+STRICT observable reach the API.
    """
    for level in [entry.value for entry in TLPLevel]:
        definition = json.loads(TLPMarking(level=level).to_stix2_object().serialize())
        assert source_tlp_levels({}, [definition]) == ([level], []), level
        expected = "clear" if level in ("clear", "white") else level
        assert effective_tlp_level({}, "clear", [definition]) == expected, level
    strict = json.loads(TLPMarking(level="amber+strict").to_stix2_object().serialize())
    assert strict["definition_type"] == "statement"
    assert refused_tlps({}, "TLP:AMBER", [strict]) == (["TLP:AMBER+STRICT"], [])
    assert refused_tlps({}, "TLP:AMBER+STRICT", [strict]) == ([], [])
    assert effective_tlp_level({}, "clear", [strict]) == "amber+strict"


def test_sdk_statement_marking_gates_before_the_api_call():
    """End to end: the sdk shape must stop the address leaving the platform."""
    StubConnectorSettings._max_tlp = "TLP:AMBER"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(side_effect=AssertionError("API was called"))
    strict = json.loads(TLPMarking(level="amber+strict").to_stix2_object().serialize())
    data = _enrichment_data()
    data["stix_entity"].pop("labels", None)
    data["stix_entity"].pop("external_references", None)
    data["stix_entity"]["object_marking_refs"] = [strict["id"]]
    data["enrichment_entity"]["objectMarking"] = []
    data["stix_objects"].append(strict)
    message = connector._process_message(data)
    assert "TLP:AMBER+STRICT" in message and "higher than" in message
    connector.client.lookup.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_tlp_marking_value_reads_every_shape():
    assert tlp_marking_value({"definition_type": "TLP", "definition": "TLP:RED"}) == (
        True,
        "TLP:RED",
    )
    assert tlp_marking_value(
        {"definition_type": "tlp", "name": "TLP:RED", "definition": {"tlp": "red"}}
    ) == (True, "TLP:RED")
    assert tlp_marking_value(
        {"definition_type": "tlp", "definition": {"tlp": "red"}}
    ) == (
        True,
        "red",
    )
    assert tlp_marking_value(
        {
            "definition_type": "statement",
            "definition": {"statement": "custom"},
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": "TLP:AMBER+STRICT",
        }
    ) == (True, "TLP:AMBER+STRICT")
    assert tlp_marking_value(
        {"definition_type": "statement", "definition": {"statement": "internal"}}
    ) == (False, None)
    assert tlp_marking_value({"definition_type": "PAP", "definition": "PAP:RED"}) == (
        False,
        None,
    )
    assert tlp_marking_value({"definition_type": "TLP", "definition": 7}) == (True, 7)


def test_live_stix2_markings_are_read_without_serialising():
    """A bundle may carry stix2 objects, not the dicts a json round trip yields.

    stix2 nests the level in a `TLPMarking` object rather than a plain dict, so
    a type check on the definition body reported every standard TLP marking as
    unreadable and the connector refused to enrich at all.
    """
    for level in [entry.value for entry in TLPLevel]:
        definition = TLPMarking(level=level).to_stix2_object()
        assert source_tlp_levels({}, [definition]) == ([level], []), level
    red = TLPMarking(level="red").to_stix2_object()
    assert refused_tlps({}, "TLP:AMBER", [red]) == (["TLP:RED"], [])


def test_materialize_marking_keeps_the_sdk_statement_shape():
    """An sdk-shaped marking must rebuild, not vanish.

    `materialize_marking` demanded a string `definition`, so a statement-shaped
    TLP marking produced nothing, no candidate definition existed for its
    reference, and the connector refused a source whose level it could in fact
    read.
    """
    strict = json.loads(TLPMarking(level="amber+strict").to_stix2_object().serialize())
    entry = {
        "standard_id": strict["id"],
        "definition_type": "statement",
        "definition": {"statement": "custom"},
        "x_opencti_definition_type": "TLP",
        "x_opencti_definition": "TLP:AMBER+STRICT",
    }
    built = materialize_marking(entry)
    assert built["id"] == strict["id"]
    assert built["definition_type"] == "statement"
    assert built["definition"] == {"statement": "custom"}
    assert built["x_opencti_definition_type"] == "TLP"
    assert built["x_opencti_definition"] == "TLP:AMBER+STRICT"
    assert built["created"] == "2017-01-20T00:00:00.000Z"
    assert source_tlp_levels({}, [built]) == (["amber+strict"], [])

    refs, missing = resolve_source_markings({}, {"objectMarking": [entry]}, [])
    assert refs == [strict["id"]]
    assert [m["id"] for m in missing] == [strict["id"]]

    del entry["standard_id"]
    assert marking_id(entry) == strict["id"]


def test_marking_refs_on_the_observable_are_collected():
    """Refs must be read from both payload halves, not just the entity.

    A reference carried on the enrichment entity rather than the stix entity
    reached neither the gate nor the note, so an AMBER limit let a TLP:RED
    observable through and the address was sent to the third-party API.
    """
    refs, _ = resolve_source_markings(
        {},
        {"objectMarking": [], "object_marking_refs": [RED_MARKING_DEF["id"]]},
        [RED_MARKING_DEF],
    )
    assert refs == [RED_MARKING_DEF["id"]]

    StubConnectorSettings._max_tlp = "TLP:AMBER"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(side_effect=AssertionError("API was called"))
    data = _enrichment_data()
    data["stix_entity"].pop("labels", None)
    data["stix_entity"].pop("external_references", None)
    data["enrichment_entity"]["objectMarking"] = []
    data["enrichment_entity"]["object_marking_refs"] = [RED_MARKING_DEF["id"]]
    data["stix_objects"].append(RED_MARKING_DEF)
    message = connector._process_message(data)
    assert "TLP:RED" in message and "higher than" in message
    connector.client.lookup.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_unresolved_marking_is_not_forwarded_at_all():
    """The refusal must not hand the bundle on, in a playbook or otherwise.

    Forwarding runs the cleanup pass, which drops a reference whose target is
    absent from the bundle. Here that reference is the whole reason for
    refusing, so forwarding stripped the source marking and republished the
    analyst's own entity unrestricted; sending it uncleaned would only trade
    that for the missing reference error the cleanup exists to avoid.
    """
    ghost = "marking-definition--00000000-0000-4000-8000-000000000000"
    for playbook in (True, False):
        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(
            side_effect=AssertionError("API was called")
        )
        data = _enrichment_data(playbook=playbook)
        data["stix_entity"]["object_marking_refs"] = [ghost]
        data["enrichment_entity"]["objectMarking"] = []
        message = connector._process_callback(data)
        assert "cannot be resolved" in message, playbook
        connector.client.lookup.assert_not_called()
        helper.send_stix2_bundle.assert_not_called()
        helper.connector_logger.error.assert_called_once()


def test_every_send_asks_for_cleanup():
    """Both send paths pass cleanup_inconsistent_bundle=True.

    The repository linter (VC312) requires the literal on every
    send_stix2_bundle call, and the one path where cleaning would have been
    destructive now refuses instead of forwarding.
    """
    for lookup in (BREACHED, {}):
        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(return_value=lookup)
        connector._process_message(_enrichment_data(playbook=True))
        assert (
            helper.send_stix2_bundle.call_args.kwargs["cleanup_inconsistent_bundle"]
            is True
        )


def test_malformed_label_and_reference_fields_are_survivable():
    """Both dual-spelling fields must tolerate what a bad payload can put there.

    The marking routes were hardened one review round at a time; labels and
    external references were left assuming a list of dicts. A bare string where
    the list belongs made `list()` iterate its characters into junk labels, and
    a non-dict reference raised AttributeError, which surfaced as a silent
    "Internal error" instead of an enrichment.
    """
    cases = [
        {"external_references": ["junk"]},
        {"external_references": [None]},
        {"external_references": {"source_name": "X"}},
        {"x_opencti_external_references": ["junk"]},
        {"x_opencti_labels": "data-breach"},
        {"x_opencti_labels": ["ok", 7, None]},
        {"labels": [7, None]},
    ]
    for overrides in cases:
        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(return_value=BREACHED)
        data = _enrichment_data()
        data["stix_entity"].pop("labels", None)
        data["stix_entity"].pop("external_references", None)
        data["stix_entity"].update(overrides)
        message = connector._process_callback(data)
        assert "Internal error" not in message, overrides
        assert "Found 1 breach" in message, overrides
        sent = helper.stix2_create_bundle.call_args[0][0]
        observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
        assert all(
            isinstance(label, str) for label in observable["x_opencti_labels"]
        ), overrides
        assert "data-breach" in observable["x_opencti_labels"], overrides
        assert all(
            hasattr(ref, "get") for ref in observable["x_opencti_external_references"]
        ), overrides


def test_a_malformed_label_does_not_fail_the_enrichment():
    """Filtering has to happen before deduplication.

    A label that is a dict or a list is unhashable, and `dict.fromkeys`
    raised on it, so one malformed entry turned into a failed enrichment
    reported as an internal error. Blank entries are dropped too.
    """
    for labels, expected in (
        (["ok", {"a": 1}], ["ok"]),
        (["ok", ["nested"]], ["ok"]),
        (["ok", 7, None], ["ok"]),
        (["", "   ", "ok"], ["ok"]),
        ([{"a": 1}], []),
    ):
        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(return_value=BREACHED)
        data = _enrichment_data()
        data["stix_entity"].pop("labels", None)
        data["stix_entity"].pop("external_references", None)
        data["stix_entity"]["x_opencti_labels"] = labels
        message = connector._process_callback(data)
        assert "Internal error" not in message, labels
        sent = helper.stix2_create_bundle.call_args[0][0]
        observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
        assert observable["x_opencti_labels"] == expected + [
            "data-breach",
            "plaintext-password-exposure",
        ], labels


def test_labels_are_deduplicated_across_both_spellings():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_entity"].pop("external_references", None)
    data["stix_entity"]["x_opencti_labels"] = ["a", "a", "b"]
    data["stix_entity"]["labels"] = ["b", "c"]
    connector._process_message(data)
    sent = helper.stix2_create_bundle.call_args[0][0]
    observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
    assert observable["x_opencti_labels"] == [
        "a",
        "b",
        "c",
        "data-breach",
        "plaintext-password-exposure",
    ]


def test_listed_reads_only_real_sequences():
    assert listed(["a", "b"]) == ["a", "b"]
    assert listed(("a",)) == ["a"]
    assert listed("data-breach") == []
    assert listed({"source_name": "X"}) == []
    assert listed(None) == []
    assert listed(7) == []


def test_malformed_marking_references_fail_closed():
    """A reference that is not a usable id must refuse, not be skipped.

    Filtering non-strings out of object_marking_refs left the observable
    looking unmarked to the gate, so a payload carrying `[None]` sailed past
    an AMBER limit and its address was sent. An empty string already refused,
    which made the two halves of the same field behave differently.
    """
    for bad in ([None], [7], [{"id": "x"}], [""], ["   "], [[]]):
        with pytest.raises(MarkingResolutionError, match="not a usable identifier"):
            resolve_source_markings({"object_marking_refs": bad}, {}, [])
        with pytest.raises(MarkingResolutionError, match="not a usable identifier"):
            resolve_source_markings({}, {"object_marking_refs": bad}, [])

        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(
            side_effect=AssertionError("API was called")
        )
        data = _enrichment_data()
        data["enrichment_entity"]["objectMarking"] = []
        data["stix_entity"]["object_marking_refs"] = bad
        message = connector._process_callback(data)
        assert "not a usable identifier" in message, bad
        connector.client.lookup.assert_not_called()
        helper.send_stix2_bundle.assert_not_called()


def test_no_forward_path_publishes_an_unresolvable_marking():
    """Every early return must refuse, not just the in-scope one.

    The scope check returns before markings are resolved, so an out-of-scope
    entity carrying an unresolvable reference was forwarded through the
    cleanup pass, which stripped that reference and republished the entity
    with weaker access control. The in-scope path already refused, so the two
    disagreed about the same bundle.
    """
    ghost = "marking-definition--00000000-0000-4000-8000-000000000000"

    def payload(entity_type="Email-Addr"):
        data = _enrichment_data(playbook=True)
        data["enrichment_entity"]["entity_type"] = entity_type
        data["enrichment_entity"]["objectMarking"] = []
        data["stix_entity"]["object_marking_refs"] = [ghost]
        return data

    paths = [
        ("out of scope", payload("IPv4-Addr"), MagicMock(return_value=BREACHED)),
        ("invalid email", payload(), MagicMock(return_value=BREACHED)),
        ("lookup failed", payload(), MagicMock(return_value=None)),
        ("no breach", payload(), MagicMock(return_value={})),
        ("internal error", payload(), MagicMock(side_effect=RuntimeError("boom"))),
    ]
    for label, data, lookup in paths:
        connector, helper = _make_connector()
        connector.client.lookup = lookup
        message = connector._process_callback(data)
        helper.send_stix2_bundle.assert_not_called()
        assert "cannot be resolved" in message, f"{label}: {message}"


def test_forward_paths_still_forward_when_markings_resolve():
    """Refusing unresolvable markings must not stop the ordinary pass-through."""
    for entity_type, lookup in (
        ("IPv4-Addr", MagicMock(return_value=BREACHED)),
        ("Email-Addr", MagicMock(return_value={})),
    ):
        connector, helper = _make_connector()
        connector.client.lookup = lookup
        data = _enrichment_data(playbook=True)
        data["enrichment_entity"]["entity_type"] = entity_type
        connector._process_message(data)
        helper.send_stix2_bundle.assert_called_once_with(
            "BUNDLE", update=False, cleanup_inconsistent_bundle=True
        )


def test_only_real_marking_identifiers_are_trusted():
    """A non-empty string is not a STIX id.

    `"not-a-stix-id"` was accepted as a marking reference and then emitted as
    both `object_marking_refs` and the rebuilt definition's own `id`,
    producing a bundle nothing could resolve. A reference must be a real
    marking id; an entry whose `standard_id` is unusable is identified from
    its definition instead, which is the authoritative half.
    """
    good = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
    assert is_marking_id(good)
    assert is_marking_id(
        good.upper().replace("MARKING-DEFINITION", "marking-definition")
    )
    for bad in (
        "not-a-stix-id",
        "marking-definition--nope",
        "identity--11111111-1111-4111-8111-111111111111",
        "http://evil",
        "",
        None,
        7,
    ):
        assert not is_marking_id(bad), bad
        with pytest.raises(MarkingResolutionError, match="not a usable identifier"):
            resolve_source_markings({"object_marking_refs": [bad]}, {}, [])

    derived = marking_id(
        {
            "standard_id": "not-a-stix-id",
            "definition_type": "TLP",
            "definition": "TLP:RED",
        }
    )
    assert derived == good
    assert (
        materialize_marking(
            {"standard_id": "bogus", "definition_type": "TLP", "definition": "TLP:RED"}
        )["id"]
        == good
    )

    for unidentifiable in (
        {"standard_id": "bogus"},
        {"standard_id": "x", "definition_type": "TLP"},
    ):
        with pytest.raises(MarkingResolutionError, match="cannot be assigned"):
            resolve_source_markings({}, {"objectMarking": [unidentifiable]}, [])


def test_malformed_marking_containers_fail_closed():
    """A marking field that is not a list of references must refuse.

    Element validation was strict while the container went through `listed`,
    which reads anything that is not a list as absent. A bare string or a
    mapping in object_marking_refs therefore left the observable looking
    unmarked and its address was sent, while objectMarking already refused the
    same shapes. `listed` is right for labels, where ignoring a malformed value
    costs a label; it is wrong here, where it costs the restriction itself.
    """
    red = RED_MARKING_DEF["id"]
    for value in (red, {"0": red}, {red: 1}, 7, True):
        with pytest.raises(MarkingResolutionError, match="not a list"):
            resolve_source_markings({"object_marking_refs": value}, {}, [])
        with pytest.raises(MarkingResolutionError, match="not a list"):
            resolve_source_markings({}, {"object_marking_refs": value}, [])

        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(
            side_effect=AssertionError("API was called")
        )
        data = _enrichment_data()
        data["enrichment_entity"]["objectMarking"] = []
        data["stix_entity"]["object_marking_refs"] = value
        message = connector._process_callback(data)
        assert "not a list" in message, value
        connector.client.lookup.assert_not_called()
        helper.send_stix2_bundle.assert_not_called()


def test_the_bundle_never_references_an_object_it_omits():
    """Every reference the bundle makes must resolve inside the bundle.

    The enriched observable was only ever substituted into the incoming
    objects, so if it was not among them it was dropped and the Note was
    published pointing at an object nobody shipped. The connector still
    reported success, and cleanup would then strip the reference and detach
    the Note. pycti always includes the entity, so this never fired, but it
    failed silently rather than loudly.
    """
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_objects"] = [{"type": "identity", "id": "identity--0000", "name": "x"}]
    connector._process_message(data)

    sent = helper.stix2_create_bundle.call_args[0][0]
    present = {o["id"] for o in sent}
    assert data["stix_entity"]["id"] in present, "the enriched observable was dropped"
    for obj in sent:
        get = getattr(obj, "get", dict().get)
        for field in ("object_refs", "object_marking_refs"):
            for ref in get(field) or []:
                assert ref in present, f"{get('type')}.{field} -> {ref} is missing"
        for field in ("created_by_ref", "x_opencti_created_by_ref"):
            ref = get(field)
            assert ref is None or ref in present, f"{get('type')}.{field} -> {ref}"


def test_our_own_reference_is_matched_whatever_its_case():
    """A stale entry spelled differently survived and gained a twin.

    The comparison was case-sensitive, so `xposedornot` was not recognised as
    ours: the old entry stayed and a second one was appended beside it. The
    same comparison decides whether the observable was enriched before, which
    drives score retraction.
    """
    for spelling in ("XposedOrNot", "xposedornot", "XPOSEDORNOT", " XposedOrNot "):
        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(return_value=BREACHED)
        data = _enrichment_data()
        data["stix_entity"].pop("external_references", None)
        data["stix_entity"]["x_opencti_external_references"] = [
            {"source_name": spelling, "url": "https://xposedornot.com"}
        ]
        connector._process_message(data)
        sent = helper.stix2_create_bundle.call_args[0][0]
        observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
        ours = [
            ref
            for ref in observable["x_opencti_external_references"]
            if is_own_reference(ref)
        ]
        assert len(ours) == 1, (spelling, observable["x_opencti_external_references"])
        assert ours[0]["source_name"] == "XposedOrNot"

    assert is_own_reference({"source_name": "xposedornot"})
    assert not is_own_reference({"source_name": "other"})
    assert not is_own_reference("not-a-dict")
    assert not is_own_reference({})


def test_references_without_a_source_or_url_are_not_collapsed():
    """Deduplication keyed on (source_name, url) merged distinct entries.

    Two references carrying only a description both keyed to (None, None) and
    the second was dropped, losing an analyst's own reference.
    """
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_entity"].pop("external_references", None)
    data["stix_entity"]["x_opencti_external_references"] = [
        {"description": "first"},
        {"description": "second"},
        {"source_name": "X", "url": "u", "description": "1"},
        {"source_name": "X", "url": "u", "description": "2"},
    ]
    connector._process_message(data)
    sent = helper.stix2_create_bundle.call_args[0][0]
    observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
    refs = observable["x_opencti_external_references"]
    assert [r.get("description") for r in refs if not r.get("source_name")] == [
        "first",
        "second",
    ]
    assert len([r for r in refs if r.get("source_name") == "X"]) == 1


def test_the_new_note_outranks_the_version_it_replaces():
    """A replaced note claiming a future `modified` would otherwise win.

    The new Note's `modified` is now, so a stale version stamped ahead of the
    clock looked newer and a platform could keep it, discarding the refreshed
    breach content.
    """
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    for stale_modified in (now - timedelta(days=1), now + timedelta(days=365)):
        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(return_value=BREACHED)
        data = _enrichment_data(playbook=True)
        note_id = ObservableNote.stable_id(data["stix_entity"]["id"])
        data["stix_objects"].append(
            {
                "type": "note",
                "spec_version": "2.1",
                "id": note_id,
                "created": "1970-01-01T00:00:00.000Z",
                "modified": stale_modified.isoformat(),
                "abstract": "XposedOrNot",
                "content": "STALE",
                "object_refs": [data["stix_entity"]["id"]],
            }
        )
        connector._process_message(data)
        sent = helper.stix2_create_bundle.call_args[0][0]
        notes = [o for o in sent if getattr(o, "get", dict().get)("type") == "note"]
        assert len(notes) == 1
        assert "STALE" not in notes[0]["content"]
        assert notes[0]["modified"] > stale_modified, stale_modified


def test_re_enrichment_replaces_a_stale_note_in_the_bundle():
    """A playbook bundle can already hold last run's Note under the same id.

    The Note id is deterministic, so the incoming bundle's copy was carried
    into the enriched objects first and `unique_by_id` kept it, discarding the
    refreshed content and the advanced `modified` marker. Marking definitions
    keep first-occurrence, which is why the Note is dropped explicitly rather
    than by reversing the dedup order.
    """
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data(playbook=True)
    note_id = ObservableNote.stable_id(data["stix_entity"]["id"])
    stale = {
        "type": "note",
        "spec_version": "2.1",
        "id": note_id,
        "created": "1970-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "abstract": "XposedOrNot",
        "content": "STALE CONTENT FROM LAST RUN",
        "object_refs": [data["stix_entity"]["id"]],
    }
    data["stix_objects"].append(stale)
    connector._process_message(data)

    sent = helper.stix2_create_bundle.call_args[0][0]
    notes = [o for o in sent if getattr(o, "get", dict().get)("type") == "note"]
    assert len(notes) == 1, "the bundle must carry exactly one Note"
    assert "STALE" not in notes[0]["content"]
    assert str(notes[0]["modified"]) > stale["modified"]

    definitions = [
        o for o in sent if getattr(o, "get", dict().get)("type") == "marking-definition"
    ]
    assert len({o["id"] for o in definitions}) == len(definitions)


def test_an_unusable_score_preserves_the_existing_one():
    """A malformed API value must not destroy a score the platform already has.

    The retraction path could not tell "the API reports no score" from "the
    API sent something unusable", so an out-of-range value wiped a good score
    from a previous run. Only a genuine absence retracts.
    """

    def run(new_score, enriched_before):
        StubConnectorSettings._max_tlp = "TLP:RED"
        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(
            return_value={"breaches": [{"name": "B"}], "risk_score": new_score}
        )
        data = _enrichment_data()
        data["stix_entity"]["x_opencti_score"] = 60
        data["stix_entity"]["x_opencti_external_references"] = (
            [{"source_name": "XposedOrNot", "url": "https://xposedornot.com"}]
            if enriched_before
            else []
        )
        data["stix_entity"].pop("external_references", None)
        connector._process_message(data)
        sent = helper.stix2_create_bundle.call_args[0][0]
        observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
        return observable.get("x_opencti_score", "<absent>")

    for unusable in (150, -5, "high", 3.7, True):
        assert run(unusable, enriched_before=True) == 60, unusable
        assert run(unusable, enriched_before=False) == 60, unusable

    assert run(None, enriched_before=True) is None
    assert run(None, enriched_before=False) == 60
    assert run(77, enriched_before=True) == 77


def test_only_a_usable_risk_score_is_published():
    """`x_opencti_score` is an integer percentage; anything else is no score.

    The API value went straight onto the observable, so a string, a bool, a
    fraction or a value outside 0-100 would have been published as the score.
    """
    assert usable_score(0) == 0
    assert usable_score(100) == 100
    assert usable_score(42.0) == 42
    for unusable in (150, -5, 101, "high", None, 3.7, 10**9, True, False, [], {}):
        assert usable_score(unusable) is None, unusable

    for raw, expected in ((150, None), ("high", None), (True, None), (77, 77)):
        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(
            return_value={**BREACHED, "risk_score": raw}
        )
        data = _enrichment_data()
        data["stix_entity"].pop("external_references", None)
        connector._process_message(data)
        sent = helper.stix2_create_bundle.call_args[0][0]
        observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
        assert observable.get("x_opencti_score") == expected, raw
        if expected is None:
            helper.connector_logger.warning.assert_called()


def test_every_tlp_level_materialises_as_the_sdk_spells_it():
    """CLEAR and AMBER+STRICT are custom statement markings, not tlp values.

    Writing them as `definition_type: tlp` produced a body stix2 refuses to
    parse against their ids, and put two different bodies under one id in the
    same bundle, where deduplication keeps whichever came first. Building
    through the sdk keeps the materialised definition and the Note's own
    marking identical for every level.
    """
    for level in ("clear", "white", "green", "amber", "amber+strict", "red"):
        built = materialize_marking(
            {"definition_type": "TLP", "definition": f"TLP:{level.upper()}"}
        )
        expected = json.loads(TLPMarking(level=level).to_stix2_object().serialize())
        assert built["id"] == expected["id"], level
        assert built["definition_type"] == expected["definition_type"], level
        assert built["definition"] == expected["definition"], level
        stix2.parse(json.dumps(built), allow_custom=True)

    strict = materialize_marking(
        {"definition_type": "TLP", "definition": "TLP:AMBER+STRICT"}
    )
    assert strict["x_opencti_definition"] == "TLP:AMBER+STRICT"
    assert source_tlp_levels({}, [strict]) == (["amber+strict"], [])


@pytest.mark.parametrize("level", ["clear", "amber+strict"])
def test_end_to_end_enrichment_with_a_custom_tlp_source(level):
    """A successful enrichment whose source carries CLEAR or AMBER+STRICT.

    The string `objectMarking` shape is what the platform sends, and the
    resulting bundle must stay parseable and carry exactly one definition for
    that marking.
    """
    StubConnectorSettings._max_tlp = "TLP:RED"
    StubConnectorSettings._tlp_level = "clear"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data(tlp=None)
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": f"TLP:{level.upper()}"}
    ]
    message = connector._process_message(data)
    assert "Found 1 breach" in message

    sent = helper.stix2_create_bundle.call_args[0][0]
    expected_id = json.loads(TLPMarking(level=level).to_stix2_object().serialize())[
        "id"
    ]
    definitions = [
        o
        for o in sent
        if getattr(o, "get", dict().get)("type") == "marking-definition"
        and o["id"] == expected_id
    ]
    assert len(definitions) == 1, "expected exactly one definition for the level"
    definition = definitions[0]
    raw = (
        definition.serialize()
        if hasattr(definition, "serialize")
        else json.dumps(definition)
    )
    stix2.parse(raw, allow_custom=True)

    observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
    note = next(o for o in sent if getattr(o, "get", dict().get)("type") == "note")
    assert expected_id in observable["object_marking_refs"]
    assert expected_id in note["object_marking_refs"]


def test_non_tlp_markings_use_the_canonical_custom_shape():
    """PAP and friends must round-trip through pycti's importer unchanged.

    The prepare_export spelling lowercases both halves, and pycti reads them
    straight back out for anything but TLP, so a PAP:RED entry returned as
    `pap` / `pap:red` and no longer matched the canonical definition its own
    id pointed at. The platform's own constants use the custom shape.
    """
    built = materialize_marking({"definition_type": "PAP", "definition": "PAP:RED"})
    assert built["definition_type"] == "statement"
    assert built["definition"] == {"statement": "custom"}
    assert built["x_opencti_definition_type"] == "PAP"
    assert built["x_opencti_definition"] == "PAP:RED"
    assert built["id"] == PyctiMarkingDefinition.generate_id("PAP", "PAP:RED")

    tlp = materialize_marking({"definition_type": "TLP", "definition": "TLP:RED"})
    assert tlp["definition_type"] == "tlp" and tlp["name"] == "TLP:RED"
    statement = materialize_marking(
        {"definition_type": "statement", "definition": "internal only"}
    )
    assert statement["definition"] == {"statement": "internal only"}


def test_no_status_message_can_carry_the_address():
    """Every message handed back must be redacted, not just the refusal one.

    Several statuses quote the payload so the operator can see what was
    refused. The address can be placed in any of those fields, and the
    returned string reaches the platform's work status, so each one is a
    disclosure route. Swept exhaustively rather than per-report: the previous
    round fixed the refusal path and left the others open.
    """
    email = "Victim@Example.com"

    def payload(observable_extra=None, entity_extra=None):
        data = _enrichment_data(email=email, playbook=True)
        data["enrichment_entity"]["objectMarking"] = []
        data["enrichment_entity"].update(observable_extra or {})
        data["stix_entity"].update(entity_extra or {})
        return data

    cases = [
        (
            "unreadable marking",
            payload(
                {"objectMarking": [{"definition_type": "TLP", "definition": email}]}
            ),
            MagicMock(return_value=BREACHED),
        ),
        (
            "unreadable definition body",
            payload(
                {
                    "objectMarking": [
                        {"definition_type": "TLP", "definition": {"tlp": email}}
                    ]
                }
            ),
            MagicMock(return_value=BREACHED),
        ),
        (
            "unsupported type",
            payload({"entity_type": f"Weird-{email}"}),
            MagicMock(return_value=BREACHED),
        ),
        (
            "unresolvable reference",
            payload(entity_extra={"object_marking_refs": [{"who": email}]}),
            MagicMock(return_value=BREACHED),
        ),
        ("lookup failed", payload(), MagicMock(return_value=None)),
        ("no breach", payload(), MagicMock(return_value={})),
        ("internal error", payload(), MagicMock(side_effect=RuntimeError(email))),
    ]
    for label, data, lookup in cases:
        connector, helper = _make_connector()
        connector.client.lookup = lookup
        message = connector._process_callback(data)
        assert email.lower() not in message.lower(), f"{label}: {message}"
        logged = json.dumps(
            [c.kwargs for c in helper.connector_logger.error.call_args_list]
        )
        assert email.lower() not in logged.lower(), f"{label} logged: {logged[:160]}"


def test_refusal_reason_is_redacted_before_it_is_logged_or_returned():
    """The refusal quotes the offending value, which may carry the address.

    MarkingResolutionError embeds repr() of the reference or entry so an
    operator can see what was wrong with it. A payload is free to put the
    observable's own address in a marking field, and that walked straight past
    the redaction every other log line goes through.
    """
    email = "Victim@Example.com"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(side_effect=AssertionError("API was called"))
    data = _enrichment_data(email=email)
    data["enrichment_entity"]["objectMarking"] = []
    data["stix_entity"]["object_marking_refs"] = [
        {"note": f"contact {email} for access"}
    ]
    message = connector._process_callback(data)
    meta = helper.connector_logger.error.call_args.kwargs["meta"]
    assert email.lower() not in json.dumps(meta).lower()
    assert email.lower() not in message.lower()
    assert "<redacted>" in message
    connector.client.lookup.assert_not_called()


def test_blank_ids_fall_back_and_unidentifiable_markings_refuse():
    """A blank standard_id is not an id, and must not silently drop a marking.

    `marking_id` accepted "" and the empty result was filtered out further
    down, so a non-TLP restriction the platform did describe vanished from the
    references without anything refusing, and the observable was published
    unmarked.
    """
    pap = {"standard_id": "", "definition_type": "PAP", "definition": "PAP:RED"}
    derived = marking_id(pap)
    assert derived and derived.startswith("marking-definition--")
    assert marking_id({"standard_id": "   ", **pap}) == derived
    assert marking_id({"definition_type": "PAP", "definition": "PAP:RED"}) == derived

    refs, missing = resolve_source_markings({}, {"objectMarking": [pap]}, [])
    assert refs == [derived] and [m["id"] for m in missing] == [derived]

    for unidentifiable in (
        {},
        {"definition_type": "PAP"},
        {"definition": "x"},
        {"standard_id": ""},
        "not-a-marking",
        None,
    ):
        with pytest.raises(MarkingResolutionError, match="cannot be assigned"):
            resolve_source_markings({}, {"objectMarking": [unidentifiable]}, [])


def test_empty_malformed_marking_containers_fail_closed():
    """An empty mapping or string is not an empty marking list.

    Iterating {} or "" yields nothing, so the observable read as unmarked on
    the strength of a field nobody could parse and its address was sent. A
    genuinely empty list must still mean exactly that.
    """
    for value in ({}, "", 0, 7, {"definition_type": "TLP"}, "TLP:RED"):
        with pytest.raises(MarkingResolutionError, match="not a list"):
            resolve_source_markings({}, {"objectMarking": value}, [])

        connector, helper = _make_connector()
        connector.client.lookup = MagicMock(
            side_effect=AssertionError("API was called")
        )
        data = _enrichment_data()
        data["enrichment_entity"]["objectMarking"] = value
        message = connector._process_callback(data)
        assert "not a list" in message, value
        connector.client.lookup.assert_not_called()

    for empty in ([], ()):
        assert resolve_source_markings({}, {"objectMarking": empty}, []) == ([], [])
    assert resolve_source_markings({}, {"objectMarking": None}, []) == ([], [])


def test_forwarded_bundle_carries_the_definitions_its_refs_need():
    """A no-op forward must not let cleanup strip a reference it can resolve.

    When the entity carries object_marking_refs but the definition arrived
    only as objectMarking, the bundle had no definition to point at, so the
    cleanup pass dropped the reference and weakened the forwarded entity.
    """
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value={})
    data = _enrichment_data(playbook=True)
    data["stix_entity"]["object_marking_refs"] = [RED_MARKING_DEF["id"]]
    data["enrichment_entity"]["objectMarking"] = [
        {
            "standard_id": RED_MARKING_DEF["id"],
            "definition_type": "TLP",
            "definition": "TLP:RED",
        }
    ]
    StubConnectorSettings._max_tlp = "TLP:RED"
    connector._process_message(data)
    forwarded = helper.stix2_create_bundle.call_args.args[0]
    definitions = {o["id"] for o in forwarded if o.get("type") == "marking-definition"}
    assert RED_MARKING_DEF["id"] in definitions
    entity = next(o for o in forwarded if o["id"] == data["stix_entity"]["id"])
    assert entity["object_marking_refs"] == [RED_MARKING_DEF["id"]]


def test_a_tuple_of_references_is_still_read():
    """Refusing malformed containers must not refuse a legitimate sequence."""
    refs, _ = resolve_source_markings(
        {"object_marking_refs": (RED_MARKING_DEF["id"],)}, {}, [RED_MARKING_DEF]
    )
    assert refs == [RED_MARKING_DEF["id"]]
    assert resolve_source_markings({"object_marking_refs": None}, {}, []) == ([], [])
    assert resolve_source_markings({}, {}, []) == ([], [])


def test_enriched_observable_keeps_its_source_markings():
    """The observable we publish must carry the markings the source had.

    A marking present only as `objectMarking` was resolved onto the Note but
    never copied to the enriched entity, so the bundle updated the observable
    with no access control at all while shipping a marking definition nothing
    pointed at. In a playbook that hands the next step an unmarked observable.
    """
    StubConnectorSettings._max_tlp = "TLP:RED"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data(tlp="TLP:RED")
    data["enrichment_entity"]["objectMarking"] = [
        {
            "standard_id": RED_MARKING_DEF["id"],
            "definition_type": "TLP",
            "definition": "TLP:RED",
        }
    ]
    data["stix_entity"].pop("object_marking_refs", None)
    connector._process_message(data)
    sent = helper.stix2_create_bundle.call_args[0][0]
    observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
    note = next(o for o in sent if getattr(o, "get", dict().get)("type") == "note")
    assert RED_MARKING_DEF["id"] in observable["object_marking_refs"]
    assert RED_MARKING_DEF["id"] in note["object_marking_refs"]

    referenced = {
        ref
        for obj in sent
        for ref in (getattr(obj, "get", dict().get)("object_marking_refs") or [])
    }
    for obj in sent:
        if getattr(obj, "get", dict().get)("type") == "marking-definition":
            assert obj["id"] in referenced, "shipped a marking nothing references"


def test_tlp_rank_agrees_with_pycti_for_every_pair():
    """The local ordering and the platform's own table must not drift apart.

    `refused_tlps` compares with pycti while `effective_tlp_level` compares with
    TLP_RANK; if the two ever disagreed, a level could pass the gate and still
    be treated as the stricter one, or the reverse.
    """
    for source in TLP_RANK:
        for configured in TLP_RANK:
            assert (
                TLP_RANK[source] <= TLP_RANK[configured]
            ) == OpenCTIConnectorHelper.check_max_tlp(
                canonical_tlp(source), canonical_tlp(configured)
            ), (
                source,
                configured,
            )


def test_non_tlp_and_absent_markings_do_not_gate():
    assert refused_tlps({}, "TLP:AMBER") == ([], [])
    assert refused_tlps({"objectMarking": None}, "TLP:AMBER") == ([], [])
    assert refused_tlps({"objectMarking": []}, "TLP:AMBER") == ([], [])
    pap = {"objectMarking": [{"definition_type": "PAP", "definition": "PAP:RED"}]}
    assert refused_tlps(pap, "TLP:AMBER") == ([], [])


def test_tlp_parsing_is_shared_by_the_gate_and_the_level():
    """Padding and case must be read the same way by both decisions."""
    for raw in ("TLP:RED", " TLP:RED ", "tlp:red"):
        observable = {"objectMarking": [{"definition_type": "TLP", "definition": raw}]}
        assert source_tlp_levels(observable) == (["red"], [])
        assert refused_tlps(observable, "TLP:AMBER") == (["TLP:RED"], [])
        assert refused_tlps(observable, "TLP:RED") == ([], [])
        assert effective_tlp_level(observable, "clear") == "red"


def test_unique_by_id_keeps_the_first_occurrence():
    first = {"id": "x", "n": 1}
    objects = [first, {"id": "x", "n": 2}, {"id": "y"}, {"no": "id"}]
    result = unique_by_id(objects)
    assert result[0] is first
    assert [o.get("id") for o in result] == ["x", "y", None]


def test_effective_tlp_level_takes_the_stricter_of_both():

    def obs(*tlps):
        return {
            "objectMarking": [{"definition_type": "TLP", "definition": t} for t in tlps]
        }

    assert effective_tlp_level(obs("TLP:RED"), "amber") == "red"
    assert effective_tlp_level(obs("TLP:CLEAR"), "red") == "red"
    assert effective_tlp_level(obs("TLP:AMBER+STRICT"), "amber") == "amber+strict"
    assert effective_tlp_level(obs("TLP:GREEN"), "amber") == "amber"
    assert effective_tlp_level(obs(), "amber") == "amber"
    assert effective_tlp_level(obs("TLP:WHITE"), "clear") == "clear"
    assert effective_tlp_level(obs("TLP:GREEN", "TLP:RED"), "amber") == "red"
    assert effective_tlp_level({"objectMarking": None}, "amber") == "amber"


def test_note_marking_never_downgrades_the_observable():
    StubConnectorSettings._max_tlp = "TLP:RED"
    StubConnectorSettings._tlp_level = "amber"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data(tlp="TLP:RED")
    connector._process_message(data)
    sent = helper.stix2_create_bundle.call_args[0][0]
    note = next(o for o in sent if getattr(o, "get", dict().get)("type") == "note")
    marking = next(
        o for o in sent if getattr(o, "get", dict().get)("type") == "marking-definition"
    )
    assert marking["id"] in note["object_marking_refs"]
    assert (marking.get("name") or marking.get("x_opencti_definition")) == "TLP:RED"


def test_settings_accept_every_sdk_tlp_level():
    for level in [entry.value for entry in TLPLevel]:
        StubConnectorSettings._tlp_level = level
        settings = StubConnectorSettings()
        assert settings.xposedornot.tlp_level == level
        XposedOrNotConnector(config=settings, helper=MagicMock())


def test_settings_reject_plain_http_base_url():
    StubConnectorSettings._api_base_url = "http://api.xposedornot.com"
    with pytest.raises(ConfigValidationError) as raised:
        StubConnectorSettings()
    assert "must use https" in str(raised.value.__cause__)
    StubConnectorSettings._api_base_url = "https://mirror.example.org/xon"
    assert str(StubConnectorSettings().xposedornot.api_base_url).startswith("https://")


def test_connector_init_keyless_and_keyed():
    connector, _ = _make_connector()
    assert connector.max_tlp == "TLP:AMBER"
    assert connector.client.api_key is None
    keyed, _ = _make_connector(api_key="SECRET")
    assert keyed.client.api_key == "SECRET"


# ---------------------------------------------------------------------------
# enrichment flow
# ---------------------------------------------------------------------------
def test_process_message_breached_updates_observable_and_sends_bundle():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    result = connector._process_message(_enrichment_data())
    assert "Found 1 breach" in result
    # the enriched observable was included in the sent bundle
    sent_objects = helper.stix2_create_bundle.call_args[0][0]
    enriched = next(o for o in sent_objects if o.get("id") == OBSERVABLE_ID)
    assert enriched["x_opencti_score"] == 100
    assert "data-breach" in enriched["x_opencti_labels"]
    assert "plaintext-password-exposure" in enriched["x_opencti_labels"]
    refs = enriched["x_opencti_external_references"]
    assert any(ref["source_name"] == "XposedOrNot" for ref in refs)
    assert isinstance(refs[0], dict)
    assert "labels" not in enriched and "external_references" not in enriched
    assert "legacy-label" in enriched["x_opencti_labels"]
    assert "Legacy Tool" in [
        ref["source_name"] for ref in enriched["x_opencti_external_references"]
    ]
    helper.send_stix2_bundle.assert_called_once()


def test_process_message_keeps_foreign_references_and_dedupes_ours():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_entity"].pop("labels", None)
    data["stix_entity"].pop("external_references", None)
    data["stix_entity"]["x_opencti_external_references"] = [
        {"source_name": "Analyst", "url": "https://example.org/case/1"},
        {"source_name": "XposedOrNot", "url": "https://old.example"},
    ]
    connector._process_message(data)
    enriched = next(
        o
        for o in helper.stix2_create_bundle.call_args[0][0]
        if o.get("id") == OBSERVABLE_ID
    )
    refs = enriched["x_opencti_external_references"]
    assert [r["source_name"] for r in refs] == ["Analyst", "XposedOrNot"]
    assert refs[1]["url"] == "https://xposedornot.com"


def test_process_message_drops_stale_owned_labels_and_keeps_foreign_ones():
    connector, helper = _make_connector()
    remediated = {
        **BREACHED,
        "breaches": [{**BREACHED["breaches"][0], "password_risk": "easytocrack"}],
    }
    connector.client.lookup = MagicMock(return_value=remediated)
    data = _enrichment_data()
    data["stix_entity"].pop("labels", None)
    data["stix_entity"]["x_opencti_labels"] = [
        "analyst-tag",
        "plaintext-password-exposure",
        "data-breach",
    ]
    connector._process_message(data)
    sent_objects = helper.stix2_create_bundle.call_args[0][0]
    enriched = next(o for o in sent_objects if o.get("id") == OBSERVABLE_ID)
    assert enriched["x_opencti_labels"] == ["analyst-tag", "data-breach"]
    assert data["stix_entity"]["x_opencti_labels"] == [
        "analyst-tag",
        "plaintext-password-exposure",
        "data-breach",
    ]


def test_note_in_the_bundle_is_anchored_to_the_observable():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    connector._process_message(_enrichment_data())
    note = next(
        o
        for o in helper.stix2_create_bundle.call_args[0][0]
        if getattr(o, "get", dict().get)("type") == "note"
    )
    assert note["created"].isoformat().startswith("2024-05-01T10:00:00")
    assert note["modified"] >= note["created"]


def test_switching_to_plus_retracts_the_stale_community_score():
    connector, helper = _make_connector(api_key="SECRET")
    plus_result = {**BREACHED, "risk_label": None, "risk_score": None}
    connector.client.lookup = MagicMock(return_value=plus_result)
    data = _enrichment_data()
    data["stix_entity"]["x_opencti_score"] = 100
    data["stix_entity"]["external_references"] = [
        {"source_name": "XposedOrNot", "url": "https://xposedornot.com"}
    ]
    connector._process_message(data)
    enriched = next(
        o
        for o in helper.stix2_create_bundle.call_args[0][0]
        if o.get("id") == OBSERVABLE_ID
    )
    assert enriched["x_opencti_score"] is None


def test_a_score_we_never_set_is_left_alone():
    connector, helper = _make_connector(api_key="SECRET")
    connector.client.lookup = MagicMock(
        return_value={**BREACHED, "risk_label": None, "risk_score": None}
    )
    data = _enrichment_data()
    data["stix_entity"]["x_opencti_score"] = 42
    data["stix_entity"]["external_references"] = [
        {"source_name": "Another Connector", "url": "https://elsewhere.test"}
    ]
    connector._process_message(data)
    enriched = next(
        o
        for o in helper.stix2_create_bundle.call_args[0][0]
        if o.get("id") == OBSERVABLE_ID
    )
    assert enriched["x_opencti_score"] == 42


def test_community_score_still_overwrites_a_previous_one():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_entity"]["x_opencti_score"] = 5
    connector._process_message(data)
    enriched = next(
        o
        for o in helper.stix2_create_bundle.call_args[0][0]
        if o.get("id") == OBSERVABLE_ID
    )
    assert enriched["x_opencti_score"] == 100


RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
CUSTOM_ID = "marking-definition--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def test_resolve_source_markings_reads_both_places():
    entity = {"object_marking_refs": [RED_ID]}
    observable = {
        "objectMarking": [
            {"definition_type": "TLP", "definition": "TLP:RED", "standard_id": RED_ID},
            {
                "definition_type": "PAP",
                "definition": "PAP:AMBER",
                "standard_id": CUSTOM_ID,
            },
        ]
    }
    refs, missing = resolve_source_markings(entity, observable, [])
    assert refs == [RED_ID, CUSTOM_ID]
    assert [d["id"] for d in missing] == [RED_ID, CUSTOM_ID]

    refs, _ = resolve_source_markings({}, observable, [])
    assert refs == [RED_ID, CUSTOM_ID]
    with pytest.raises(MarkingResolutionError):
        resolve_source_markings(entity, {"objectMarking": []}, [])
    assert resolve_source_markings({}, {}, []) == ([], [])


def test_markings_known_only_from_object_marking_reach_the_note():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_entity"].pop("object_marking_refs", None)
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": "TLP:AMBER", "standard_id": RED_ID},
        {"definition_type": "PAP", "definition": "PAP:AMBER", "standard_id": CUSTOM_ID},
    ]
    connector._process_message(data)
    sent = helper.stix2_create_bundle.call_args[0][0]
    note = next(o for o in sent if getattr(o, "get", dict().get)("type") == "note")
    present = {
        o["id"]
        for o in sent
        if getattr(o, "get", dict().get)("type") == "marking-definition"
    }
    assert CUSTOM_ID in note["object_marking_refs"]
    assert CUSTOM_ID in present


def test_materialize_marking_mirrors_the_platform_shape():
    tlp = materialize_marking(
        {"definition_type": "TLP", "definition": "TLP:RED", "standard_id": RED_ID}
    )
    assert tlp["id"] == RED_ID and tlp["definition_type"] == "tlp"
    assert tlp["definition"] == {"tlp": "red"} and tlp["name"] == "TLP:RED"
    statement = materialize_marking(
        {
            "definition_type": "statement",
            "definition": "Internal only",
            "standard_id": CUSTOM_ID,
            "created": "2024-01-01T00:00:00.000Z",
        }
    )
    assert statement["created"] == "2024-01-01T00:00:00.000Z"
    assert statement["definition"] == {"statement": "internal only"}
    assert materialize_marking({"definition_type": "TLP"}) is None
    assert materialize_marking({}) is None


def test_resolve_source_markings_reuses_bundled_and_refuses_unknown():
    entity = {"object_marking_refs": [RED_ID, CUSTOM_ID]}
    observable = {
        "objectMarking": [
            {"definition_type": "TLP", "definition": "TLP:RED", "standard_id": RED_ID},
            {
                "definition_type": "statement",
                "definition": "Internal only",
                "standard_id": CUSTOM_ID,
            },
        ]
    }
    already = [{"type": "marking-definition", "id": RED_ID}]
    refs, missing = resolve_source_markings(entity, observable, already)
    assert refs == [RED_ID, CUSTOM_ID]
    assert [d["id"] for d in missing] == [CUSTOM_ID]

    _, from_object_marking = resolve_source_markings({}, observable, [])
    assert [d["id"] for d in from_object_marking] == [RED_ID, CUSTOM_ID]
    assert resolve_source_markings({}, {}, []) == ([], [])

    with pytest.raises(MarkingResolutionError, match="refusing to enrich"):
        resolve_source_markings(entity, {"objectMarking": []}, [])


def test_bundle_never_repeats_a_marking_definition():
    """The connector builds its own marking for the Note; when the platform
    already bundled the same definition the bundle must not carry it twice."""
    amber_id = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_entity"]["object_marking_refs"] = [amber_id]
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": "TLP:AMBER", "standard_id": amber_id}
    ]
    data["stix_objects"].append(
        {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": amber_id,
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": "TLP:AMBER",
            "definition": {"tlp": "amber"},
        }
    )
    connector._process_message(data)
    sent = helper.stix2_create_bundle.call_args[0][0]
    identifiers = [o["id"] for o in sent if getattr(o, "get", dict().get)("id")]
    assert len(identifiers) == len(set(identifiers))


def test_callback_traceback_hides_the_observable_and_the_key():
    connector, helper = _make_connector(api_key="SUPERSECRET")

    def boom(email):
        raise ValueError(f"rejected {email} with key SUPERSECRET")

    connector.client.lookup = boom
    assert "Internal error" in connector._process_callback(_enrichment_data())
    logged = str(helper.connector_logger.error.call_args)
    assert "test@example.com" not in logged
    assert "SUPERSECRET" not in logged
    assert "<redacted>" in logged


def test_bundle_carries_every_source_marking_definition():
    StubConnectorSettings._max_tlp = "TLP:RED"
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data(tlp="TLP:RED")
    data["stix_entity"]["object_marking_refs"] = [RED_ID, CUSTOM_ID]
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": "TLP:RED", "standard_id": RED_ID},
        {
            "definition_type": "statement",
            "definition": "Internal only",
            "standard_id": CUSTOM_ID,
        },
    ]
    connector._process_message(data)
    sent = helper.stix2_create_bundle.call_args[0][0]
    present = {
        o["id"]
        for o in sent
        if getattr(o, "get", dict().get)("type") == "marking-definition"
    }
    assert {RED_ID, CUSTOM_ID} <= present


def test_unresolvable_marking_fails_instead_of_downgrading():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    data = _enrichment_data()
    data["stix_entity"]["object_marking_refs"] = [CUSTOM_ID]
    data["enrichment_entity"]["objectMarking"] = []
    message = connector._process_callback(data)
    assert "refusing to enrich" in message
    assert "Internal error" not in message
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_clean_email_modifies_nothing():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value={})
    result = connector._process_message(_enrichment_data())
    assert "No known breach exposure" in result
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_tlp_exceeded_skips_before_lookup():
    connector, _ = _make_connector()
    connector.client.lookup = MagicMock()
    result = connector._process_message(_enrichment_data(tlp="TLP:RED"))
    assert "higher than" in result
    connector.client.lookup.assert_not_called()


def test_process_message_refuses_when_any_marking_exceeds_max_tlp():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock()
    data = _enrichment_data(tlp="TLP:GREEN")
    data["enrichment_entity"]["objectMarking"].append(
        {"definition_type": "TLP", "definition": "TLP:RED"}
    )
    result = connector._process_message(data)
    assert "TLP:RED" in result and "higher than" in result
    connector.client.lookup.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def _assert_forwarded_intact(helper, data):
    """The forwarded bundle keeps every original object and adds only markings.

    It is not byte-identical to the input any more: a definition the platform
    sent only as `objectMarking` has to travel with the bundle, or the cleanup
    pass drops the reference pointing at it and weakens the very entity being
    handed back untouched.
    """
    passed = helper.stix2_create_bundle.call_args.args[0]
    assert passed is not data["stix_objects"]
    for original in data["stix_objects"]:
        assert original in passed, "a forwarded object was dropped or altered"
    added = [obj for obj in passed if obj not in data["stix_objects"]]
    assert all(obj.get("type") == "marking-definition" for obj in added), added
    referenced = {
        ref for obj in passed for ref in (obj.get("object_marking_refs") or [])
    }
    for obj in added:
        assert obj["id"] in referenced, "added a marking nothing references"
    helper.send_stix2_bundle.assert_called_once_with(
        "BUNDLE", update=False, cleanup_inconsistent_bundle=True
    )


def test_send_bundle_copies_input_and_requests_cleanup():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value={})
    data = _enrichment_data(playbook=True)
    connector._process_message(data)
    _assert_forwarded_intact(helper, data)


def test_process_message_unsupported_type_and_invalid_email():
    connector, _ = _make_connector()
    data = _enrichment_data()
    data["enrichment_entity"]["entity_type"] = "IPv4-Addr"
    assert "Unsupported type" in connector._process_message(data)

    connector.client.lookup = MagicMock()
    bad = _enrichment_data(email="not-an-email")
    assert "not a valid email" in connector._process_message(bad)
    connector.client.lookup.assert_not_called()


def test_process_message_api_failure_and_callback_guard():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=None)
    assert "request failed" in connector._process_message(_enrichment_data())
    helper.send_stix2_bundle.assert_not_called()
    connector._process_message = MagicMock(side_effect=RuntimeError("boom"))
    assert "Internal error" in connector._process_callback(_enrichment_data())
    helper.send_stix2_bundle.assert_not_called()


def test_playbook_run_detection():
    assert is_playbook_run({"stix_objects": []})
    assert not is_playbook_run({"event_type": "INTERNAL_ENRICHMENT"})


@pytest.mark.parametrize(
    "mutate, lookup, expected",
    [
        (
            lambda d: d["enrichment_entity"].update(entity_type="IPv4-Addr"),
            None,
            "Unsupported",
        ),
        (
            lambda d: d["enrichment_entity"].update(
                objectMarking=[{"definition_type": "TLP", "definition": "TLP:RED"}]
            ),
            None,
            "higher than",
        ),
        (
            lambda d: d["enrichment_entity"].update(observable_value="nope"),
            None,
            "not a valid email",
        ),
        (lambda d: None, None, "request failed"),
        (lambda d: None, {}, "No known breach"),
    ],
)
def test_playbook_noop_paths_forward_original_bundle(mutate, lookup, expected):
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=lookup)
    data = _enrichment_data(playbook=True)
    mutate(data)
    assert expected in connector._process_message(data)
    _assert_forwarded_intact(helper, data)


def test_playbook_error_forwards_original_bundle():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(side_effect=RuntimeError("boom"))
    data = _enrichment_data(playbook=True)
    assert "Internal error" in connector._process_callback(data)
    _assert_forwarded_intact(helper, data)
    helper.connector_logger.error.assert_called_once()


def test_playbook_error_while_forwarding_is_contained():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(side_effect=RuntimeError("boom"))
    helper.send_stix2_bundle.side_effect = RuntimeError("queue down")
    assert "Internal error" in connector._process_callback(
        _enrichment_data(playbook=True)
    )
    assert helper.connector_logger.error.call_count == 2


def test_playbook_breached_sends_enriched_bundle_once():
    connector, helper = _make_connector()
    connector.client.lookup = MagicMock(return_value=BREACHED)
    assert "Found 1 breach" in connector._process_message(
        _enrichment_data(playbook=True)
    )
    helper.send_stix2_bundle.assert_called_once_with(
        "BUNDLE", update=True, cleanup_inconsistent_bundle=True
    )
