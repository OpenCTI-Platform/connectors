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
    "ipgeolocation": {"api_key": "test-api-key"},
}


def test_minimal_settings_use_the_documented_defaults():
    settings = _settings(MINIMAL)

    assert isinstance(settings.ipgeolocation, BaseConfigModel)
    assert settings.connector.name == "IPGeolocation.io"
    assert settings.connector.scope == ["IPv4-Addr", "IPv6-Addr"]
    assert settings.connector.auto is False  # every lookup spends credits
    config = settings.ipgeolocation
    assert config.api_key.get_secret_value() == "test-api-key"
    assert str(config.api_base_url) == "https://api.ipgeolocation.io/"
    assert config.include_security and config.include_abuse and config.include_hostname
    assert config.max_tlp_level == "amber+strict"
    assert config.tlp_level == "clear"
    assert config.create_indicator is False  # indicators often feed detection tools
    assert config.indicator_threshold == 50


def test_booleans_and_numbers_are_parsed_from_strings():
    """Environment variables arrive as strings: "false" must turn a feature off."""
    settings = _settings(
        {
            **MINIMAL,
            "connector": {"id": "connector-id", "auto": "false"},
            "ipgeolocation": {
                "api_key": "test-api-key",
                "include_security": "false",
                "create_indicator": "true",
                "indicator_threshold": "80",
                "max_tlp_level": "green",
            },
        }
    )

    assert settings.connector.auto is False
    assert settings.ipgeolocation.include_security is False
    assert settings.ipgeolocation.create_indicator is True
    assert settings.ipgeolocation.indicator_threshold == 80
    assert settings.ipgeolocation.max_tlp_level == "green"


def test_api_key_is_not_shown_in_repr():
    settings = _settings(MINIMAL)

    assert "test-api-key" not in repr(settings.ipgeolocation)


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty"),
        pytest.param(
            {**MINIMAL, "ipgeolocation": {}},
            id="missing_api_key",
        ),
        pytest.param(
            {**MINIMAL, "ipgeolocation": {"api_key": ""}},
            id="empty_api_key",
        ),
        pytest.param(
            {**MINIMAL, "ipgeolocation": {"api_key": "k", "indicator_threshold": 101}},
            id="threshold_above_100",
        ),
        pytest.param(
            {**MINIMAL, "ipgeolocation": {"api_key": "k", "max_tlp_level": "TLP:PINK"}},
            id="unknown_tlp",
        ),
        pytest.param(
            {**MINIMAL, "connector": {"scope": "IPv4-Addr"}},
            id="missing_connector_id",
        ),
    ],
)
def test_invalid_settings_are_rejected(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        _settings(settings_dict)
    assert "Error validating configuration" in str(err)
