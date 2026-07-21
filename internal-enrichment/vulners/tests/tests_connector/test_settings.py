from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Vulners",
                    "scope": "Vulnerability",
                    "log_level": "error",
                    "auto": True,
                },
                "vulners": {
                    "api_key": "test-api-key",
                    "api_base_url": "https://vulners.com",
                    "max_tlp_level": "TLP:AMBER",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                },
                "vulners": {
                    "api_key": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """`ConnectorSettings` accepts valid input and applies Vulners defaults."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.vulners, BaseConfigModel) is True

    # Defaults from VulnersConfig / InternalEnrichmentConnectorConfig
    assert settings.connector.name == "Vulners"
    assert settings.connector.scope == ["Vulnerability"]
    assert settings.vulners.api_base_url == "https://vulners.com"
    assert settings.vulners.max_tlp_level == "TLP:AMBER"


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Vulnerability",
                },
                "vulners": {
                    # api_key is missing
                    "api_base_url": "https://vulners.com",
                },
            },
            "vulners.api_key",
            id="missing_vulners_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "scope": "Vulnerability",
                },
                "vulners": {
                    "api_key": "test-api-key",
                },
            },
            "connector.id",
            id="missing_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """`ConnectorSettings` raises `ConfigValidationError` on invalid input."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
