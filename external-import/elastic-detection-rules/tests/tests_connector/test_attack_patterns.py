from unittest.mock import MagicMock

import pytest
from connector.attack_patterns import (
    AttackPatternResolver,
    attack_pattern_id,
    extract_technique_ids,
    normalize_technique_id,
)
from pycti import AttackPattern, Identity, MarkingDefinition

AUTHOR_ID = Identity.generate_id("Vendor", "organization")
MARKING_ID = MarkingDefinition.generate_id("TLP", "TLP:AMBER")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("T1059", "T1059"),
        ("t1059.001", "T1059.001"),
        (" T1003 ", "T1003"),
        ("T105", None),
        ("T1059.01", None),
        ("TA0002", None),
        ("execution", None),
        (None, None),
        (1059, None),
    ],
)
def test_normalize_technique_id(value, expected):
    assert normalize_technique_id(value) == expected


@pytest.mark.parametrize(
    "texts,expected",
    [
        (["Detects T1059.001 and T1003"], ["T1059.001", "T1003"]),
        (["(T1059.001)."], ["T1059.001"]),
        (["T1059, T1059 again"], ["T1059"]),
        (["https://attack.mitre.org/techniques/T1055/012/"], ["T1055.012"]),
        (["see attack.mitre.org/techniques/T1105"], ["T1105"]),
        # Lowercase ids, parts of words, hashes and malformed ids never match.
        (["t1059 XT1059 T1059X T10590 T1059.0011 v1.T1059"], []),
        (["sha T1234ab", "T12345"], []),
        ([None, ""], []),
        (["T1003", "T1059 then T1003"], ["T1003", "T1059"]),
    ],
)
def test_extract_technique_ids(texts, expected):
    assert extract_technique_ids(*texts) == expected


def test_attack_pattern_id_depends_on_the_mitre_id_only():
    assert attack_pattern_id("T1059") == AttackPattern.generate_id(
        "Command and Scripting Interpreter", "T1059"
    )


def _resolver(pages):
    helper = MagicMock()
    helper.api.attack_pattern.list.side_effect = pages
    return AttackPatternResolver(helper)


def test_known_techniques_are_referenced_only():
    resolver = _resolver(
        [
            [
                {"standard_id": attack_pattern_id("T1059"), "x_opencti_stix_ids": []},
                {
                    "standard_id": AttackPattern.generate_id("OS Credential Dumping"),
                    "x_opencti_stix_ids": [attack_pattern_id("T1003")],
                },
            ]
        ]
    )
    resolver.load(["T1059", "T1003", "T1105"])

    assert resolver.build("T1059", "Command", AUTHOR_ID, MARKING_ID) is None
    assert resolver.build("T1003", None, AUTHOR_ID, MARKING_ID) is None
    created = resolver.build("T1105", "Ingress Tool Transfer", AUTHOR_ID, MARKING_ID)
    assert created.id == attack_pattern_id("T1105")
    assert created.name == "Ingress Tool Transfer"
    assert created.x_mitre_id == "T1105"
    assert created.created_by_ref == AUTHOR_ID
    assert created.object_marking_refs == [MARKING_ID]


def test_unknown_technique_without_vendor_name_uses_its_id():
    resolver = _resolver([[]])
    resolver.load(["T1105"])
    assert resolver.build("T1105", None, AUTHOR_ID, MARKING_ID).name == "T1105"


def test_lookup_is_batched():
    resolver = _resolver([[], [], []])
    resolver.load([f"T{1000 + index}" for index in range(201)])
    calls = resolver.helper.api.attack_pattern.list.call_args_list
    assert [len(c.kwargs["filters"]["filters"][0]["values"]) for c in calls] == [
        100,
        100,
        1,
    ]


def test_no_lookup_without_techniques():
    resolver = _resolver([])
    resolver.load([])
    resolver.helper.api.attack_pattern.list.assert_not_called()


def test_lookup_errors_propagate():
    resolver = _resolver(RuntimeError("platform down"))
    with pytest.raises(RuntimeError):
        resolver.load(["T1059"])
