from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from internal_enrichment_connector.settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
}

FULL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "Indicator",
        "log_level": "error",
        "auto": True,
        "max_tlp": "amber",
    },
    "connector_scoring": {
        "high_priority_labels": '["[Scoring] High priority"]',
        "medium_priority_labels": '["[Scoring] Medium priority"]',
        "low_priority_labels": '["[Scoring] Low priority"]',
        "indicator_type_enrichable": "IPv4-Addr,IPv6-Addr,Domain-Name,StixFile",
        "browse_report": True,
        "threat_impact_score": True,
        "threat_high_priority": 20,
        "threat_medium_priority": 10,
        "threat_low_priority": 5,
        "toolbox_impact_score": True,
        "toolbox_high_priority": 20,
        "toolbox_medium_priority": 10,
        "toolbox_low_priority": 5,
        "location_impact_score": True,
        "location_high_priority": 20,
        "location_medium_priority": 10,
        "location_low_priority": 5,
        "sector_impact_score": True,
        "sector_high_priority": 20,
        "sector_medium_priority": 10,
        "sector_low_priority": 5,
        "ttp_impact_score": True,
        "ttp_high_priority": 20,
        "ttp_medium_priority": 10,
        "ttp_low_priority": 5,
        "author_impact_score": True,
        "author_high_priority": 20,
        "author_medium_priority": 10,
        "author_low_priority": 5,
    },
}


def _build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env/config vars."""

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return the given config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    settings = _build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.connector_scoring, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """The minimal settings dict MUST yield the documented defaults."""
    settings = _build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Scoring calculator"
    assert settings.connector.scope == ["Indicator"]
    assert settings.connector.log_level == "error"
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.auto is False

    scoring = settings.connector_scoring
    assert scoring.high_priority_labels == []
    assert scoring.medium_priority_labels == []
    assert scoring.low_priority_labels == []
    assert (
        scoring.indicator_type_enrichable == "IPv4-Addr,IPv6-Addr,Domain-Name,StixFile"
    )
    assert scoring.browse_report is False
    for category in ("threat", "toolbox", "location", "sector", "ttp", "author"):
        assert getattr(scoring, f"{category}_impact_score") is False
        assert getattr(scoring, f"{category}_high_priority") == 0
        assert getattr(scoring, f"{category}_medium_priority") == 0
        assert getattr(scoring, f"{category}_low_priority") == 0


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = _build_settings({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    assert settings.connector.id == "1f5865dc-085a-4b71-98a5-58ad6f03acf5"
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "value",
    [
        pytest.param('["[Scoring] High priority", "Critical"]', id="json_string"),
        pytest.param(["[Scoring] High priority", "Critical"], id="yaml_list"),
    ],
)
def test_settings_should_parse_label_lists(value):
    """A JSON string (env var) and a YAML list (config.yml) MUST both give a list."""
    settings = _build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "connector_scoring": {"high_priority_labels": value},
        }
    )

    assert settings.connector_scoring.high_priority_labels == [
        "[Scoring] High priority",
        "Critical",
    ]


@pytest.mark.parametrize("value", [None, "", []])
def test_settings_should_accept_empty_label_lists(value):
    """An empty field in an existing `config.yml` MUST give an empty list."""
    settings = _build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "connector_scoring": {"high_priority_labels": value},
        }
    )

    assert settings.connector_scoring.high_priority_labels == []


def test_settings_should_coerce_string_values():
    """String values (env vars, quoted YAML values) MUST be coerced to their types."""
    settings = _build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "connector_scoring": {
                "threat_impact_score": "true",
                "threat_high_priority": "20",
            },
        }
    )

    assert settings.connector_scoring.threat_impact_score is True
    assert settings.connector_scoring.threat_high_priority == 20


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"id": 123456},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector_scoring": {"threat_high_priority": "high"},
            },
            id="invalid_priority_impact",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    with pytest.raises(ConfigValidationError) as err:
        _build_settings(settings_dict)
    assert str("Error validating configuration") in str(err)
