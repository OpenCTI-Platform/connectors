from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _settings(settings_dict: dict) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


MINIMAL = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id"},
    "whoisfreaks": {"api_key": "test-api-key"},
}


def test_minimal_settings_use_the_documented_defaults():
    settings = _settings(MINIMAL)

    assert isinstance(settings.whoisfreaks, BaseConfigModel)
    assert settings.connector.name == "WhoisFreaks"
    assert settings.connector.scope == ["Domain-Name"]
    assert settings.connector.auto is False  # every lookup spends credits
    assert settings.connector.max_tlp == "amber+strict"
    config = settings.whoisfreaks
    assert config.api_key.get_secret_value() == "test-api-key"
    assert str(config.api_base_url) == "https://api.whoisfreaks.com/"
    assert config.timeout == 30
    assert config.tlp_level == "clear"
    assert config.create_labels and config.create_relationships and config.create_note


def test_booleans_are_parsed_from_strings():
    """Environment variables arrive as strings: "false" must turn a feature off."""
    settings = _settings(
        {
            **MINIMAL,
            "connector": {"id": "connector-id", "auto": "true", "max_tlp": "green"},
            "whoisfreaks": {
                "api_key": "test-api-key",
                "create_note": "false",
                "timeout": "10",
            },
        }
    )

    assert settings.connector.auto is True
    assert settings.connector.max_tlp == "green"
    assert settings.whoisfreaks.create_note is False
    assert settings.whoisfreaks.timeout == 10


def test_api_key_is_not_shown_in_repr():
    settings = _settings(MINIMAL)

    assert "test-api-key" not in repr(settings.whoisfreaks)


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty"),
        pytest.param({**MINIMAL, "whoisfreaks": {}}, id="missing_api_key"),
        pytest.param({**MINIMAL, "whoisfreaks": {"api_key": ""}}, id="empty_api_key"),
        pytest.param(
            {**MINIMAL, "whoisfreaks": {"api_key": "k", "timeout": 0}},
            id="timeout_below_one",
        ),
        pytest.param(
            {**MINIMAL, "connector": {"id": "c", "max_tlp": "TLP:PINK"}},
            id="unknown_tlp",
        ),
        pytest.param(
            {**MINIMAL, "connector": {"scope": "Domain-Name"}},
            id="missing_connector_id",
        ),
    ],
)
def test_invalid_settings_are_rejected(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        _settings(settings_dict)
    assert "Error validating configuration" in str(err)
