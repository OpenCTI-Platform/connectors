from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Cyble Vision",
                    "scope": "Incident",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "cyble_vision": {
                    "api_token": "test-api-token",
                },
            },
            id="minimal_valid_settings",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.cyble_vision, BaseConfigModel)
    assert settings.cyble_vision.api_token.get_secret_value() == "test-api-token"


def test_settings_should_raise_when_token_missing():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "cyble_vision": {},
                }
            )

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    assert "Error validating configuration" in str(err.value)
    assert "cyble_vision.api_token" in str(err.value.__cause__)
