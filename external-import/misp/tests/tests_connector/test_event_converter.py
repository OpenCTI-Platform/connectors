import pytest
from connector.use_cases.convert_event import (
    DEFAULT_THREAT_LEVEL_SCORE_MAPPING,
    event_threat_level_to_opencti_score,
)


@pytest.mark.parametrize(
    "threat_level, expected",
    [
        ("1", 90),
        ("2", 60),
        ("3", 30),
        ("4", 50),
    ],
)
def test_event_threat_level_to_opencti_score_default_mapping(threat_level, expected):
    """When called without an explicit mapping, the function reproduces the
    legacy hard-coded behavior (1=90, 2=60, 3=30, 4=50) so upgrading users
    who do not configure ``MISP_THREAT_LEVEL_SCORE_MAPPING`` keep getting
    identical scores.
    """
    assert event_threat_level_to_opencti_score(threat_level) == expected


def test_event_threat_level_to_opencti_score_unknown_value_falls_back_to_level_4():
    """MISP can return a ``threat_level_id`` outside ``[1, 4]`` (older
    instances, custom forks). Such values must resolve to the score
    associated with level ``"4"`` (Undefined) rather than raising.
    """
    assert event_threat_level_to_opencti_score("5") == 50
    assert event_threat_level_to_opencti_score("99") == 50


def test_event_threat_level_to_opencti_score_uses_custom_mapping():
    """The function honors the mapping provided by the caller, both for
    known levels and for the fallback (level ``"4"``).
    """
    mapping = {"1": 100, "2": 70, "3": 40, "4": 10}
    assert event_threat_level_to_opencti_score("1", mapping) == 100
    assert event_threat_level_to_opencti_score("2", mapping) == 70
    assert event_threat_level_to_opencti_score("3", mapping) == 40
    assert event_threat_level_to_opencti_score("4", mapping) == 10
    # Unknown threat-level resolves to the "Undefined" score.
    assert event_threat_level_to_opencti_score("foo", mapping) == 10


def test_default_threat_level_score_mapping_matches_legacy_behavior():
    """The module-level default mapping must mirror the historic
    hard-coded values so the behavior is preserved when no override
    is supplied at runtime.
    """
    assert DEFAULT_THREAT_LEVEL_SCORE_MAPPING == {
        "1": 90,
        "2": 60,
        "3": 30,
        "4": 50,
    }
