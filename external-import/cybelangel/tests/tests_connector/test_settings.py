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
                    "name": "CybelAngel",
                    "scope": "all",
                    "log_level": "error",
                    "duration_period": "PT6H",
                },
                "cybelangel": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "api_url": "https://platform.cybelangel.com",
                    "auth_url": "https://auth.cybelangel.com/oauth/token",
                    "audience": "https://platform.cybelangel.com/",
                    "marking": "TLP:AMBER+STRICT",
                    "fetch_period": "7",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "cybelangel": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` accepts valid input.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.cybelangel, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "CybelAngel",
                    "scope": "all",
                    "log_level": "error",
                    "duration_period": "PT6H",
                },
                "cybelangel": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "CybelAngel",
                    "scope": "all",
                    "log_level": "error",
                    "duration_period": "PT6H",
                },
                "cybelangel": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` raises `ConfigValidationError` on invalid input.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
