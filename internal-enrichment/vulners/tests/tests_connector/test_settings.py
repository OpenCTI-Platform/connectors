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
                    "max_tlp": "TLP:AMBER",
                },
                "vulners": {
                    "api_key": "test-api-key",
                    "api_base_url": "https://vulners.com",
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
    assert settings.connector.max_tlp == "TLP:AMBER"


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


def test_settings_should_migrate_deprecated_vulners_max_tlp_level_to_connector_max_tlp():
    """The deprecated `VULNERS_MAX_TLP_LEVEL` is migrated to `CONNECTOR_MAX_TLP`."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id"},
                    "vulners": {"api_key": "test-api-key", "max_tlp_level": "TLP:RED"},
                }
            )

    with pytest.warns(UserWarning, match="vulners.max_tlp_level"):
        settings = FakeConnectorSettings()

    assert settings.connector.max_tlp == "TLP:RED"
