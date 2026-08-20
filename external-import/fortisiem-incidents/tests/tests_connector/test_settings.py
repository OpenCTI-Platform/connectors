from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _valid_settings() -> dict[str, Any]:
    return {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {
            "id": "connector-id",
            "name": "FortiSIEM Incidents",
            "scope": "fortisiem",
            "log_level": "error",
            "duration_period": "PT15M",
        },
        "fortisiem_incidents": {
            "api_base_url": "https://fortisiem.example.com",
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

    assert isinstance(settings.fortisiem_incidents, BaseConfigModel) is True
    assert settings.fortisiem_incidents.organization == "super"
    assert settings.fortisiem_incidents.import_window_days == 7
    assert settings.fortisiem_incidents.tlp_level == "amber"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "fortisiem",
                    "duration_period": "PT15M",
                },
                "fortisiem_incidents": {
                    "username": "api-user",
                    "password": "test-password",
                },
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

    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        FakeConnectorSettings()
