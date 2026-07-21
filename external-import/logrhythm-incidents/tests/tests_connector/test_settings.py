from typing import Any, Self

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _valid_settings() -> dict[str, Any]:
    return {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {
            "id": "connector-id",
            "name": "LogRhythm Incidents",
            "scope": "logrhythm",
            "log_level": "error",
            "duration_period": "PT15M",
        },
        "logrhythm_incidents": {
            "api_base_url": "https://logrhythm.example.com:8501",
            "api_token": "test-token",
        },
    }


def test_settings_should_accept_valid_input():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> Self:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert isinstance(settings.logrhythm_incidents, BaseConfigModel) is True
    assert settings.logrhythm_incidents.max_cases == 200
    assert settings.logrhythm_incidents.tlp_level == "amber"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "logrhythm",
                    "duration_period": "PT15M",
                },
                "logrhythm_incidents": {
                    "max_cases": 200,
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
