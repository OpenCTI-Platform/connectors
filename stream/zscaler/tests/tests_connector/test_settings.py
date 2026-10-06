from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from stream_connector.settings import ConnectorSettings


def _full_valid_settings() -> dict[str, Any]:
    """A configuration dict setting every field (required + optional)."""
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "Zscaler",
            "scope": "domain-name",
            "log_level": "info",
            "live_stream_id": "live-stream-id",
            "live_stream_listen_delete": True,
            "live_stream_no_dependencies": True,
        },
        "zscaler": {
            "username": "zscaler-user",
            "password": "zscaler-password",
            "api_key": "zscaler-api-key",
            "blacklist_name": "BLACK_LIST_DYNDNS",
            "ssl_verify": False,
        },
    }


def _minimal_valid_settings() -> dict[str, Any]:
    """A configuration dict setting only the required fields."""
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "live_stream_id": "live-stream-id",
        },
        "zscaler": {
            "username": "zscaler-user",
            "password": "zscaler-password",
            "api_key": "zscaler-api-key",
        },
    }


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(_full_valid_settings(), id="full_valid_settings_dict"),
        pytest.param(_minimal_valid_settings(), id="minimal_valid_settings_dict"),
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
    assert isinstance(settings.zscaler, BaseConfigModel) is True
    # Required values are exposed as validated Pydantic settings.
    assert settings.connector.live_stream_id == "live-stream-id"
    assert settings.zscaler.username == "zscaler-user"
    assert settings.zscaler.password.get_secret_value() == "zscaler-password"
    assert settings.zscaler.api_key.get_secret_value() == "zscaler-api-key"


def test_settings_should_apply_defaults():
    """Optional fields fall back to the defaults declared in settings.py."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_minimal_valid_settings())

    settings = FakeConnectorSettings()

    assert settings.connector.name == "Zscaler"
    assert settings.connector.scope == ["domain-name"]
    assert settings.connector.log_level == "info"
    assert settings.connector.live_stream_listen_delete is True
    assert settings.connector.live_stream_no_dependencies is True
    assert settings.zscaler.blacklist_name == "BLACK_LIST_DYNDNS"
    assert settings.zscaler.ssl_verify is False


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "live_stream_id": "live-stream-id",
                },
                "zscaler": {
                    "username": "zscaler-user",
                    "password": "zscaler-password",
                    "api_key": "zscaler-api-key",
                },
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123,
                    "live_stream_id": "live-stream-id",
                },
                "zscaler": {
                    "username": "zscaler-user",
                    "password": "zscaler-password",
                    "api_key": "zscaler-api-key",
                },
            },
            id="invalid_connector_id",
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
