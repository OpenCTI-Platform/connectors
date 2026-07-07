from typing import Any, Self

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _valid_settings() -> dict[str, Any]:
    return {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {
            "id": "connector-id",
            "name": "Swimlane",
            "scope": "swimlane",
            "log_level": "error",
            "duration_period": "PT15M",
        },
        "swimlane": {
            "api_base_url": "https://swimlane.example.com",
            "api_token": "test-token",
            "application_id": "app-123",
        },
    }


def test_settings_should_accept_valid_input():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert isinstance(settings.swimlane, BaseConfigModel) is True
    assert settings.swimlane.max_records == 100
    assert settings.swimlane.tlp_level == "amber"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "swimlane",
                    "duration_period": "PT15M",
                },
                "swimlane": {
                    "api_base_url": "https://swimlane.example.com",
                    "api_token": "test-token",
                },
            },
            id="missing_application_id",
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
