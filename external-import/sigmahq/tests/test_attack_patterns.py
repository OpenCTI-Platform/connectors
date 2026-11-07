"""Tests for the platform-aware Attack Pattern resolution."""

from unittest.mock import MagicMock

import pytest
import stix2
from connector.attack_patterns import AttackPatternResolver, attack_pattern_id
from pycti import AttackPattern, Identity

AUTHOR = stix2.Identity(
    id=Identity.generate_id("SigmaHQ", "organization"),
    name="SigmaHQ",
    identity_class="organization",
)


def _resolver(pages: list[list[dict]]) -> AttackPatternResolver:
    helper = MagicMock()
    helper.api.attack_pattern.list.side_effect = pages
    return AttackPatternResolver(helper)


def test_attack_pattern_id_is_keyed_on_the_mitre_id_only():
    assert attack_pattern_id("T1059") == AttackPattern.generate_id(
        "Command and Scripting Interpreter", "T1059"
    )


def test_known_technique_keeps_its_platform_name_and_carries_no_author():
    resolver = _resolver(
        [
            [
                {
                    "standard_id": attack_pattern_id("T1059"),
                    "x_opencti_stix_ids": [],
                    "name": "Command and Scripting Interpreter",
                }
            ]
        ]
    )
    resolver.load(["T1059", "T1059.001"])

    known = resolver.build("T1059", AUTHOR, stix2.TLP_WHITE)
    assert known.id == attack_pattern_id("T1059")
    assert known.name == "Command and Scripting Interpreter"
    assert known.x_mitre_id == "T1059"
    assert "created_by_ref" not in known
    assert "object_marking_refs" not in known

    missing = resolver.build("T1059.001", AUTHOR, stix2.TLP_WHITE)
    assert missing.name == "T1059.001"
    assert missing.created_by_ref == AUTHOR.id
    assert missing.object_marking_refs == [stix2.TLP_WHITE.id]


def test_match_through_an_aliased_stix_id():
    resolver = _resolver(
        [
            [
                {
                    "standard_id": AttackPattern.generate_id("OS Credential Dumping"),
                    "x_opencti_stix_ids": [attack_pattern_id("T1003")],
                    "name": "OS Credential Dumping",
                }
            ]
        ]
    )
    resolver.load(["T1003"])
    assert resolver.platform_name("T1003") == "OS Credential Dumping"


def test_lookup_is_batched_and_bounded():
    resolver = _resolver([[], [], []])
    resolver.load([f"T{1000 + i}" for i in range(250)])

    calls = resolver.helper.api.attack_pattern.list.call_args_list
    assert len(calls) == 3
    sizes = [len(call.kwargs["filters"]["filters"][0]["values"]) for call in calls]
    assert sizes == [100, 100, 50]
    assert all(call.kwargs["filters"]["filters"][0]["key"] == "ids" for call in calls)


def test_no_lookup_without_techniques():
    resolver = _resolver([])
    resolver.load([])
    resolver.helper.api.attack_pattern.list.assert_not_called()


def test_reload_forgets_the_previous_run():
    resolver = _resolver(
        [
            [
                {
                    "standard_id": attack_pattern_id("T1059"),
                    "x_opencti_stix_ids": None,
                    "name": "Command and Scripting Interpreter",
                }
            ],
            [],
        ]
    )
    resolver.load(["T1059"])
    assert resolver.platform_name("T1059") is not None
    resolver.load(["T1059"])
    assert resolver.platform_name("T1059") is None


def test_lookup_errors_propagate():
    helper = MagicMock()
    helper.api.attack_pattern.list.side_effect = RuntimeError("platform down")
    with pytest.raises(RuntimeError):
        AttackPatternResolver(helper).load(["T1059"])
