from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import ConfigValidationError
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "beaconbeagle": {},
}

FULL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "BeaconBeagle",
        "scope": "beaconbeagle",
        "log_level": "error",
        "duration_period": "PT4H",
    },
    "beaconbeagle": {
        "url": "https://beaconbeagle.com/api/v1/c2?q=&sort=firsttime",
        "add_urls": True,
        "add_useragent": True,
        "link_tool": "CobaltStrike",
        "link_ap": "T1071 Standard Application Layer Protocol",
        "link_country": True,
        "link_bgpas": True,
        "search_bgpas": False,
        "link_watermark_txt": " [CobaltStrikeLicenceWatermark]",
        "links_duration": 12,
        "marking": "TLP:AMBER",
    },
}


def _settings_class(config_dict: dict[str, Any]) -> type[ConnectorSettings]:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(config_dict)

    return FakeConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """Valid configurations (full and minimal) MUST be accepted."""
    settings = _settings_class(settings_dict)()

    assert settings.opencti.token.get_secret_value() == "test-token"
    assert isinstance(settings.to_helper_config(), dict)


def test_settings_should_apply_defaults_on_minimal_input():
    """Optional BeaconBeagle fields MUST fall back on the historical defaults."""
    settings = _settings_class(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.name == "BeaconBeagle"
    assert settings.connector.scope == ["beaconbeagle"]
    assert settings.beaconbeagle.add_urls is False
    assert settings.beaconbeagle.add_useragent is False
    assert settings.beaconbeagle.link_tool == ""
    assert settings.beaconbeagle.link_watermark_txt == ""
    assert settings.beaconbeagle.links_duration == 24
    assert settings.connector.duration_period == timedelta(hours=2)
    assert settings.beaconbeagle.marking == "TLP:GREEN"


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "opencti", id="empty_settings_dict"),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "opencti": {"url": "http://localhost:8080"},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "connector": {"id": 123}},
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "beaconbeagle": {"marking": "TLP:PINK"}},
            "beaconbeagle.marking",
            id="unknown_marking",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """Invalid configurations MUST raise a `ConfigValidationError`."""
    with pytest.raises(ConfigValidationError) as err:
        _settings_class(settings_dict)()

    assert "Error validating configuration" in str(err.value)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = _settings_class({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})()

    assert settings.connector.id == "13cc97e9-a3c7-4b06-8c8e-e2e8d85e1a98"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_split_scope_with_spaces():
    """A comma-separated scope with spaces MUST give a clean list."""
    settings = _settings_class(
        {**MINIMAL_VALID_SETTINGS_DICT, "connector": {"scope": "A, B"}}
    )()

    assert settings.connector.scope == ["A", "B"]


def test_settings_should_migrate_renamed_yaml_keys():
    """The former config.yml keys MUST still be honoured through deprecations."""
    with pytest.warns(UserWarning, match="Deprecated setting"):
        settings = _settings_class(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "beaconbeagle": {
                    "marking_definition": "TLP:RED",
                    "link_watermark": " [wm]",
                },
            }
        )()

    assert settings.beaconbeagle.marking == "TLP:RED"
    assert settings.beaconbeagle.link_watermark_txt == " [wm]"


def test_settings_should_migrate_interval_to_duration_period():
    """The former `interval` key (hours) MUST become `connector.duration_period`."""
    with pytest.warns(UserWarning, match="Deprecated setting"):
        settings = _settings_class(
            {**MINIMAL_VALID_SETTINGS_DICT, "beaconbeagle": {"interval": 6}}
        )()

    assert settings.connector.duration_period == timedelta(hours=6)


def test_settings_should_prefer_duration_period_when_interval_is_also_set():
    """`connector.duration_period` MUST win over the deprecated `interval`."""
    with pytest.warns(UserWarning, match="Using only"):
        settings = _settings_class(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"duration_period": "PT12H"},
                "beaconbeagle": {"interval": 6},
            }
        )()

    assert settings.connector.duration_period == timedelta(hours=12)


def test_settings_should_prefer_marking_when_marking_definition_is_also_set():
    """`marking` MUST win over the deprecated `marking_definition`."""
    with pytest.warns(UserWarning, match="Using only"):
        settings = _settings_class(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "beaconbeagle": {
                    "marking": "TLP:AMBER",
                    "marking_definition": "TLP:RED",
                },
            }
        )()

    assert settings.beaconbeagle.marking == "TLP:AMBER"


def test_settings_should_prefer_link_watermark_txt_when_link_watermark_is_also_set():
    """`link_watermark_txt` MUST win over the deprecated `link_watermark`."""
    with pytest.warns(UserWarning, match="Using only"):
        settings = _settings_class(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "beaconbeagle": {
                    "link_watermark_txt": " [new]",
                    "link_watermark": " [old]",
                },
            }
        )()

    assert settings.beaconbeagle.link_watermark_txt == " [new]"
