"""Tests for the prediction of empty sub-entity calls from inline relationships."""

from types import SimpleNamespace

import pytest
from connector.src.custom.client_api.inline_relationships import (
    INLINE_DESCRIPTOR_LIMIT,
    inline_relationships_param,
    is_subentity_call_needed,
)
from connector.src.custom.orchestrators.base_orchestrator import BaseOrchestrator

CURSOR = {"cursor": "eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9"}


def _assoc(*ids: str, meta: dict | None = None) -> dict:
    block: dict = {"data": [{"type": "collection", "id": i} for i in ids]}
    if meta is not None:
        block["meta"] = meta
    return {"associations": block}


def _ttp(count: int, meta: dict | None = None) -> dict:
    block: dict = {
        "data": [
            {"type": "attack_technique", "id": f"T{1000 + i}"} for i in range(count)
        ]
    }
    if meta is not None:
        block["meta"] = meta
    return {"attack_techniques": block}


# --- Scenario: no descriptors, the call is always made -----------------------


@pytest.mark.parametrize("relationships", [None, {}])
def test_call_needed_when_no_relationships(relationships):
    """Given no inline descriptors, when predicting, then every call is made."""
    for subentity_type in ("malware_families", "attack_techniques", "files"):
        assert is_subentity_call_needed(subentity_type, relationships) is True


def test_call_needed_when_block_missing():
    """Given descriptors without the needed block, then the call is made."""
    assert is_subentity_call_needed("attack_techniques", _assoc()) is True
    assert is_subentity_call_needed("threat_actors", _ttp(0)) is True


# --- Scenario: association prefixes ------------------------------------------


@pytest.mark.parametrize(
    ("ids", "subentity_type", "expected"),
    [
        (("threat-actor--1",), "threat_actors", True),
        (("threat-actor--1",), "malware_families", False),
        (("vulnerability--1",), "vulnerabilities", True),
        (("campaign--1",), "campaigns", True),
        (("report--1",), "reports", True),
        (("report--1",), "campaigns", False),
        # malware-- covers malware families AND software toolkits
        (("malware--1",), "malware_families", True),
        (("malware--1",), "software_toolkits", True),
        (("software-toolkit--1",), "software_toolkits", True),
        (("software-toolkit--1",), "malware_families", False),
        # ids without a prefix (community sources) have an unknown type
        (("malpedia_ios_predator",), "malware_families", True),
        (("malpedia_ios_predator",), "software_toolkits", True),
        (("malpedia_ios_predator",), "threat_actors", True),
        (("malpedia_ios_predator",), "vulnerabilities", True),
        (("report--1", "malpedia_ios_predator"), "campaigns", True),
        ((), "malware_families", False),
        ((), "vulnerabilities", False),
    ],
)
def test_association_prefixes(ids, subentity_type, expected):
    """Given association descriptors, then only matching types are called."""
    assert is_subentity_call_needed(subentity_type, _assoc(*ids)) is expected


def test_truncated_associations_always_called():
    """Given 20 descriptors and a cursor, then every association call is made."""
    relationships = _assoc(*[f"campaign--{i}" for i in range(20)], meta=CURSOR)
    assert is_subentity_call_needed("malware_families", relationships) is True
    assert is_subentity_call_needed("threat_actors", relationships) is True


@pytest.mark.parametrize(
    ("count", "expected"),
    [(INLINE_DESCRIPTOR_LIMIT - 1, False), (INLINE_DESCRIPTOR_LIMIT, True)],
)
def test_full_page_without_cursor_is_incomplete(count, expected):
    """Given a full page of descriptors and no cursor, then the call is made."""
    associations = _assoc(*[f"campaign--{i}" for i in range(count)])
    assert is_subentity_call_needed("threat_actors", associations) is expected
    assert is_subentity_call_needed("attack_techniques", _ttp(count)) is True
    assert is_subentity_call_needed("attack_techniques", _ttp(0)) is False


def test_indicator_types_not_predicted():
    """Given IOC sub-entity types, then the prediction never skips them."""
    for subentity_type in ("domains", "files", "urls", "ip_addresses"):
        assert is_subentity_call_needed(subentity_type, _assoc()) is True


LINKS_ONLY = {"links": {"self": "https://example.test/relationships"}}


@pytest.mark.parametrize("block", [LINKS_ONLY, {**LINKS_ONLY, "data": None}])
@pytest.mark.parametrize(
    ("relationship", "subentity_type"),
    [
        ("associations", "malware_families"),
        ("associations", "threat_actors"),
        ("attack_techniques", "attack_techniques"),
    ],
)
def test_block_without_data_list_keeps_the_call(block, relationship, subentity_type):
    """Given a block with missing or null data, then the call is made."""
    relationships = {relationship: block}
    assert is_subentity_call_needed(subentity_type, relationships) is True


# --- Scenario: attack techniques ---------------------------------------------


def test_attack_techniques():
    """Given TTP descriptors, then the call is made only when some exist."""
    assert is_subentity_call_needed("attack_techniques", _ttp(3)) is True
    assert is_subentity_call_needed("attack_techniques", _ttp(0)) is False
    assert is_subentity_call_needed("attack_techniques", _ttp(0, meta=CURSOR)) is True


# --- Scenario: combined with the counters filter in the orchestrator ---------


def test_filter_combines_counters_and_inline_relationships():
    """Given counters and descriptors, then both filters apply."""
    entity = SimpleNamespace(
        attributes=SimpleNamespace(counters=SimpleNamespace(attack_techniques=0)),
        relationships={**_assoc("threat-actor--1"), **_ttp(0)},
    )
    result = BaseOrchestrator._filter_subentity_types(
        ["malware_families", "attack_techniques", "threat_actors"], entity
    )
    assert result == ["threat_actors"]


def test_filter_keeps_everything_without_relationships():
    """Given an entity from a list call without relationships=, then no change."""
    entity = SimpleNamespace(attributes=None, relationships=None)
    types = ["malware_families", "attack_techniques", "threat_actors"]
    assert BaseOrchestrator._filter_subentity_types(types, entity) == types


# --- Scenario: the list call only asks for useful relationships --------------


@pytest.mark.parametrize(
    ("subentity_types", "expected"),
    [
        (None, "associations,attack_techniques"),
        ([], None),
        (["domains", "files", "urls", "ip_addresses"], None),
        (["attack_techniques", "files"], "attack_techniques"),
        (["malware_families", "files"], "associations"),
        (["threat_actors", "attack_techniques"], "associations,attack_techniques"),
    ],
)
def test_inline_relationships_param(subentity_types, expected):
    """Given configured sub-entity types, then only useful blocks are asked for."""
    assert inline_relationships_param(subentity_types) == expected
