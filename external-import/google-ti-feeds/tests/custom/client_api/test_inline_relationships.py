"""Tests for the prediction of empty sub-entity calls from inline relationships."""

from types import SimpleNamespace

import pytest
from connector.src.custom.client_api.inline_relationships import (
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
        # ids without a prefix (community sources) can be malware or toolkit
        (("malpedia_ios_predator",), "malware_families", True),
        (("malpedia_ios_predator",), "software_toolkits", True),
        (("malpedia_ios_predator",), "threat_actors", False),
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


def test_indicator_types_not_predicted():
    """Given IOC sub-entity types, then the prediction never skips them."""
    for subentity_type in ("domains", "files", "urls", "ip_addresses"):
        assert is_subentity_call_needed(subentity_type, _assoc()) is True


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
