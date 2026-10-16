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
            "client_id": "zscaler-client-id",
            "client_secret": "zscaler-client-secret",
            "vanity_domain": "acme",
            "cloud": "beta",
            "blacklist_name": "CUSTOM_01",
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
            "client_id": "zscaler-client-id",
            "client_secret": "zscaler-client-secret",
            "vanity_domain": "acme",
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
    assert settings.zscaler.client_id == "zscaler-client-id"
    assert settings.zscaler.client_secret.get_secret_value() == "zscaler-client-secret"
    assert settings.zscaler.vanity_domain == "acme"


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
    assert settings.zscaler.cloud is None
    assert settings.zscaler.blacklist_name == "BLACK_LIST_DYNDNS"
    assert settings.zscaler.ssl_verify is True


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
                    "client_id": "zscaler-client-id",
                    "client_secret": "zscaler-client-secret",
                    "vanity_domain": "acme",
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
                    "client_id": "zscaler-client-id",
                    "client_secret": "zscaler-client-secret",
                    "vanity_domain": "acme",
                },
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
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
            id="legacy_credentials_only",
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


def test_settings_should_accept_deprecated_legacy_credentials():
    """Legacy credentials left in the configuration do not prevent startup."""
    settings_dict = _minimal_valid_settings()
    settings_dict["zscaler"]["username"] = "zscaler-user"

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert "username" in settings.zscaler.model_fields_set
    assert settings.zscaler.client_id == "zscaler-client-id"
