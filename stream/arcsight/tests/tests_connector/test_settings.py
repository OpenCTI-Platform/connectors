from typing import Any, Self

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _valid_settings() -> dict[str, Any]:
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "ArcSight",
            "scope": "arcsight",
            "log_level": "error",
            "live_stream_id": "live",
        },
        "arcsight": {
            "api_base_url": "https://arcsight.example.com:8443",
            "username": "api-user",
            "password": "test-password",
            "active_list_id": "ABC123",
        },
    }


def test_settings_should_accept_valid_input():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert isinstance(settings.arcsight, BaseConfigModel)
    assert settings.arcsight.value_column == "value"
    assert settings.arcsight.ssl_verify is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "arcsight",
                    "live_stream_id": "live",
                },
                "arcsight": {
                    "api_base_url": "https://arcsight.example.com:8443",
                    "username": "api-user",
                    "password": "test-password",
                },
            },
            id="missing_active_list_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err.value)
