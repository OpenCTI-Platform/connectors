from typing import Any

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
            "name": "FortiEDR",
            "scope": "fortiedr",
            "log_level": "error",
            "live_stream_id": "live",
        },
        "fortiedr": {
            "api_base_url": "https://console.fortiedr.example.com",
            "username": "api-user",
            "password": "test-password",
        },
    }


def test_settings_should_accept_valid_input():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.fortiedr, BaseConfigModel) is True
    assert settings.fortiedr.ip_set_name == "OpenCTI"
    assert settings.fortiedr.ssl_verify is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "fortiedr",
                    "live_stream_id": "live",
                },
                "fortiedr": {"username": "api-user", "password": "test-password"},
            },
            id="missing_api_base_url",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
