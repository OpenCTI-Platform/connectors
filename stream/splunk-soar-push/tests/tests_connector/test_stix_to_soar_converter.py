from unittest.mock import MagicMock

import pytest
from splunk_soar_connector.stix_to_soar_converter import (
    convert_indicator_to_artifact,
    convert_observable_to_artifact,
    get_severity_from_score,
)


@pytest.fixture
def helper() -> MagicMock:
    helper = MagicMock()
    helper.get_attribute_in_extension.return_value = None
    return helper


def make_indicator(pattern: str, pattern_type: str = "stix", **kwargs) -> dict:
    return {
        "type": "indicator",
        "id": "indicator--a6f1c4a4-7c4c-4a7e-9d6b-2f1e5c3d8b90",
        "name": "Test indicator",
        "pattern": pattern,
        "pattern_type": pattern_type,
        **kwargs,
    }


@pytest.mark.parametrize(
    "score, expected",
    [
        (100, "high"),
        (80, "high"),
        (79, "medium"),
        (50, "medium"),
        (49, "low"),
        (20, "low"),
        (19, "informational"),
        (0, "informational"),
    ],
)
def test_get_severity_from_score_maps_score(score: int, expected: str) -> None:
    assert get_severity_from_score({"x_opencti_score": score}, "low") == expected


def test_get_severity_from_score_inherits_default_without_score() -> None:
    assert get_severity_from_score({"type": "ipv4-addr"}, "high") == "high"


def test_get_severity_from_score_maps_stix_severity_without_score() -> None:
    assert get_severity_from_score({"severity": "critical"}, "low") == "high"


def test_indicator_with_stix_pattern_propagates_score(helper: MagicMock) -> None:
    indicator = make_indicator("[ipv4-addr:value = '1.2.3.4']", x_opencti_score=85)

    artifacts = convert_indicator_to_artifact(indicator, helper, "low")

    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact["name"] == "1.2.3.4"
    assert artifact["severity"] == "high"
    assert artifact["data"]["opencti_score"] == 85
    assert artifact["data"]["from_indicator"] is True


def test_indicator_with_composite_pattern_propagates_score_to_all(
    helper: MagicMock,
) -> None:
    indicator = make_indicator(
        "[ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'evil.com']",
        x_opencti_score=30,
    )

    artifacts = convert_indicator_to_artifact(indicator, helper, "high")

    assert [a["name"] for a in artifacts] == ["1.2.3.4", "evil.com"]
    assert {a["severity"] for a in artifacts} == {"low"}
    assert {a["data"]["opencti_score"] for a in artifacts} == {30}


def test_indicator_with_stix_pattern_without_score_inherits_container_severity(
    helper: MagicMock,
) -> None:
    indicator = make_indicator("[domain-name:value = 'evil.com']")

    artifacts = convert_indicator_to_artifact(indicator, helper, "low")

    assert len(artifacts) == 1
    assert artifacts[0]["severity"] == "low"
    assert artifacts[0]["data"]["opencti_score"] is None


def test_indicator_without_parseable_pattern_uses_its_score(
    helper: MagicMock,
) -> None:
    indicator = make_indicator(
        "rule test { condition: true }", pattern_type="yara", x_opencti_score=60
    )

    artifacts = convert_indicator_to_artifact(indicator, helper, "low")

    assert len(artifacts) == 1
    assert artifacts[0]["label"] == "indicator"
    assert artifacts[0]["severity"] == "medium"
    assert artifacts[0]["data"]["opencti_score"] == 60


def test_bare_observable_uses_its_score(helper: MagicMock) -> None:
    observable = {"type": "ipv4-addr", "value": "1.2.3.4", "x_opencti_score": 10}

    artifact = convert_observable_to_artifact(observable, helper, "high")

    assert artifact["severity"] == "informational"
    assert artifact["data"]["opencti_score"] == 10


def test_bare_observable_without_score_inherits_container_severity(
    helper: MagicMock,
) -> None:
    observable = {"type": "ipv4-addr", "value": "1.2.3.4"}

    artifact = convert_observable_to_artifact(observable, helper, "high")

    assert artifact["severity"] == "high"
    assert artifact["data"]["opencti_score"] is None
