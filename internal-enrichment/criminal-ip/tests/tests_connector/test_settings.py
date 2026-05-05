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
                    "name": "Criminal IP",
                    "scope": "IPv4-Addr, Domain-Name",
                    "log_level": "error",
                    "auto": True,
                },
                "criminal_ip": {
                    "token": "my-secret-api-key",
                    "max_tlp": "TLP:AMBER",
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
                "connector": {"id": "connector-id"},
                "criminal_ip": {"token": "my-secret-api-key"},
            },
            id="minimal_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "https://opencti.example.com",
                    "token": "test-token",
                },
                "connector": {
                    "id": "some-id",
                },
                "criminal_ip": {
                    "token": "my-secret-api-key",
                    "max_tlp": "TLP:RED",
                },
            },
            id="valid_settings_with_max_tlp_red",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Criminal IP",
                    "scope": "IPv4-Addr",
                },
                "criminal_ip": {
                    "token": "my-secret-api-key",
                    "max_tlp": "TLP:CLEAR",
                },
            },
            id="valid_settings_single_scope",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.criminal_ip, BaseConfigModel) is True


def test_settings_defaults():
    """Test that default values are properly set."""
    settings_dict = {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {"id": "connector-id"},
        "criminal_ip": {"token": "my-secret-api-key"},
    }

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert settings.connector.name == "Criminal IP"
    assert settings.connector.scope == ["IPv4-Addr", "Domain-Name"]
    assert settings.criminal_ip.max_tlp == "TLP:AMBER"


def test_settings_token_is_secret():
    """Test that the token is stored as a SecretStr."""
    settings_dict = {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {"id": "connector-id"},
        "criminal_ip": {"token": "super-secret-key"},
    }

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert settings.criminal_ip.token.get_secret_value() == "super-secret-key"
    # Ensure the token is not exposed in string representation
    assert "super-secret-key" not in str(settings.criminal_ip.token)


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
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {},
                "criminal_ip": {"token": "my-secret-api-key"},
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "criminal_ip": {
                    "max_tlp": "TLP:AMBER",
                },
            },
            "criminal_ip.token",
            id="missing_criminal_ip_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "criminal_ip": {
                    "token": "my-secret-api-key",
                    "max_tlp": "INVALID_TLP",
                },
            },
            "criminal_ip.max_tlp",
            id="invalid_max_tlp_value",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)
