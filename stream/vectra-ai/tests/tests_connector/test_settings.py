from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _valid_settings() -> dict[str, Any]:
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "Vectra AI Intel",
            "scope": "vectra-ai",
            "log_level": "error",
            "live_stream_id": "live",
        },
        "vectra_ai": {
            "api_base_url": "https://vectra.example.com",
            "api_token": "test-api-token",
        },
    }


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(_valid_settings(), id="minimal_valid_settings_dict"),
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
    assert isinstance(settings.vectra_ai, BaseConfigModel) is True


def test_settings_should_apply_vectra_defaults():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_valid_settings())

    settings = FakeConnectorSettings()

    assert settings.vectra_ai.api_version == "v2.5"
    assert settings.vectra_ai.feed_name == "OpenCTI"
    assert settings.vectra_ai.feed_category == "cnc"
    assert settings.vectra_ai.feed_certainty == "High"
    assert settings.vectra_ai.feed_duration == 14
    assert settings.vectra_ai.ssl_verify is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "vectra-ai",
                    "live_stream_id": "live",
                },
                "vectra_ai": {"api_token": "test-api-token"},
            },
            "vectra_ai.api_base_url",
            id="missing_api_base_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "vectra-ai",
                    "live_stream_id": "live",
                },
                "vectra_ai": {
                    "api_base_url": "https://vectra.example.com",
                    "api_token": "test-api-token",
                    "feed_category": "not-a-valid-category",
                },
            },
            "vectra_ai.feed_category",
            id="invalid_feed_category",
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
    assert str("Error validating configuration") in str(err)
