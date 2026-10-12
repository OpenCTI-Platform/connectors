from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel


def _settings_class(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings


def test_settings_should_accept_minimal_input():
    # Given only the mandatory values
    FakeConnectorSettings = _settings_class(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "spur": {"api_key": "test-api-key"},
        }
    )

    # When the settings are loaded
    settings = FakeConnectorSettings()

    # Then the defaults are applied
    assert isinstance(settings.connector, BaseConfigModel)
    assert settings.connector.name == "Spur Enrichment"
    assert settings.connector.scope == ["IPv4-Addr", "IPv6-Addr"]
    assert settings.connector.auto is False
    assert settings.connector.max_tlp == TLPLevel.AMBER
    assert str(settings.spur.api_base_url) == "https://api.spur.us/"
    assert settings.spur.api_key.get_secret_value() == "test-api-key"
    assert settings.spur.tlp_level == "amber"
    assert settings.spur.default_score == 70


def test_settings_should_accept_full_input():
    # Given every Spur value
    FakeConnectorSettings = _settings_class(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {"max_tlp": "amber+strict"},
            "spur": {
                "api_base_url": "http://test.com",
                "api_key": "test-api-key",
                "tlp_level": "green",
                "default_score": 50,
            },
        }
    )

    # When the settings are loaded
    settings = FakeConnectorSettings()

    # Then the values are kept
    assert settings.connector.max_tlp == TLPLevel.AMBER_STRICT
    assert settings.spur.tlp_level == "green"
    assert settings.spur.default_score == 50


@pytest.mark.parametrize(
    "spur_config",
    [
        pytest.param({}, id="missing_api_key"),
        pytest.param({"api_key": "key", "tlp_level": "orange"}, id="invalid_tlp"),
        pytest.param({"api_key": "key", "default_score": 101}, id="score_too_high"),
    ],
)
def test_settings_should_raise_when_invalid_input(spur_config):
    # Given an invalid Spur configuration
    FakeConnectorSettings = _settings_class(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "spur": spur_config,
        }
    )

    # When / Then the settings cannot be loaded
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
