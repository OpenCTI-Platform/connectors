from typing import Any, Self

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _valid_settings() -> dict[str, Any]:
    return {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {
            "id": "connector-id",
            "name": "ArcSight Incidents",
            "scope": "arcsight",
            "log_level": "error",
            "duration_period": "PT15M",
        },
        "arcsight_incidents": {
            "api_base_url": "https://arcsight.example.com:8443",
            "username": "api-user",
            "password": "test-password",
        },
    }


def test_settings_should_accept_valid_input():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert isinstance(settings.arcsight_incidents, BaseConfigModel) is True
    assert settings.arcsight_incidents.max_cases == 200
    assert settings.arcsight_incidents.tlp_level == "amber"


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
                    "duration_period": "PT15M",
                },
                "arcsight_incidents": {
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
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err.value)
