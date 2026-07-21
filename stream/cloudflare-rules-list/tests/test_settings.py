from typing import Any

import pytest
from cloudflare_rules_list import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "cloudflare",
                    "log_level": "error",
                    "live_stream_id": "live",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                    "sync_interval": "30m",
                },
                "cloudflare": {
                    "account_id": "ChangeMe",
                    "api_token": "ChangeMe",
                    "list_id": "ChangeMe",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "cloudflare",
                    "log_level": "error",
                    "live_stream_id": "live",
                },
                "cloudflare": {
                    "account_id": "ChangeMe",
                    "api_token": "ChangeMe",
                    "list_id": "ChangeMe",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """`ConnectorSettings` accepts valid input and exposes typed namespaces."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.cloudflare, BaseConfigModel) is True


def test_settings_defaults_are_applied():
    """Optional connector fields fall back to their declared defaults."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "live_stream_id": "live",
                    },
                    "cloudflare": {
                        "account_id": "acc",
                        "api_token": "secret",
                        "list_id": "list",
                    },
                }
            )

    settings = FakeConnectorSettings()
    assert settings.connector.name == "Cloudflare Rules List"
    assert settings.connector.scope == ["cloudflare"]
    assert settings.connector.sync_interval == "1h"
    assert settings.cloudflare.api_base_url == "https://api.cloudflare.com/client/v4"


def test_settings_api_token_is_secret():
    """The Cloudflare API token is wrapped as a SecretStr and not leaked in repr."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id", "live_stream_id": "live"},
                    "cloudflare": {
                        "account_id": "acc",
                        "api_token": "super-secret",
                        "list_id": "list",
                    },
                }
            )

    settings = FakeConnectorSettings()
    assert settings.cloudflare.api_token.get_secret_value() == "super-secret"
    assert "super-secret" not in repr(settings.cloudflare.api_token)


def test_to_helper_config_returns_dict():
    """`to_helper_config` (inherited) returns a dict for OpenCTIConnectorHelper."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id", "live_stream_id": "live"},
                    "cloudflare": {
                        "account_id": "acc",
                        "api_token": "secret",
                        "list_id": "list",
                    },
                }
            )

    settings = FakeConnectorSettings()
    assert isinstance(settings.to_helper_config(), dict)


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {"id": "connector-id", "live_stream_id": "live"},
                "cloudflare": {
                    "account_id": "acc",
                    "api_token": "secret",
                    "list_id": "list",
                },
            },
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "live_stream_id": "live"},
                "cloudflare": {"account_id": "acc"},
            },
            id="missing_cloudflare_fields",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """`ConnectorSettings` raises a validation error on invalid/incomplete input."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)
