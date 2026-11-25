from copy import deepcopy
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "stixify": {
        "api_key": "test-api-key",
        "dossier_ids": "dossier-1,dossier-2",
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env vars or config files."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(deepcopy(settings_dict))

    return FakeConnectorSettings()


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
                    "id": "5b5ab1c0-5e44-4e4f-9b1c-0c9e1c4b6f6d",
                    "name": "Test Stixify",
                    "scope": "stixify,test",
                    "log_level": "info",
                    "duration_period": "PT12H",
                },
                "stixify": {
                    "base_url": "https://test-stixify-url/",
                    "api_key": "test-api-key",
                    "dossier_ids": "dossier-1,dossier-2",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    settings = build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.stixify, BaseConfigModel)
    assert settings.stixify.api_key.get_secret_value() == "test-api-key"
    assert settings.stixify.dossier_ids == ["dossier-1", "dossier-2"]


def test_settings_should_apply_defaults():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Stixify"
    assert settings.connector.scope == ["stixify"]
    assert settings.connector.log_level == "error"
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert str(settings.stixify.base_url) == "https://api.stixify.com/"


def test_settings_should_default_dossier_ids_to_empty_list():
    settings = build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "stixify": {"api_key": "test-api-key"},
        }
    )

    assert settings.stixify.dossier_ids == []


def test_settings_should_default_connector_id():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == "773ede4d-ae39-4bbb-a656-f67951f2fcee"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_trim_dossier_ids():
    settings = build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "stixify": {
                "api_key": "test-api-key",
                "dossier_ids": " dossier-1 , dossier-2,",
            },
        }
    )

    assert settings.stixify.dossier_ids == ["dossier-1", "dossier-2"]


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "stixify": {
                    "api_key": "test-api-key",
                    "dossier_ids": "dossier-1",
                },
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"id": 123456},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "stixify": {"dossier_ids": "dossier-1"},
            },
            id="missing_stixify_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)

    assert "Error validating configuration" in str(err.value)


def test_settings_should_migrate_deprecated_interval_hours():
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "stixify": {
            **MINIMAL_VALID_SETTINGS_DICT["stixify"],
            "interval_hours": "12",
        },
    }

    with pytest.warns(UserWarning, match="stixify.interval_hours"):
        settings = build_settings(settings_dict)

    assert settings.connector.duration_period == timedelta(hours=12)


def test_settings_should_prefer_duration_period_over_interval_hours():
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"duration_period": "PT6H"},
        "stixify": {
            **MINIMAL_VALID_SETTINGS_DICT["stixify"],
            "interval_hours": "12",
        },
    }

    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = build_settings(settings_dict)

    assert settings.connector.duration_period == timedelta(hours=6)


@pytest.mark.parametrize(
    "base_url",
    ["api.example.com", "ftp://api.example.com", "not a url"],
)
def test_settings_should_reject_invalid_base_url(base_url):
    """`stixify.base_url` must be an absolute HTTP(S) URL."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "stixify": {**MINIMAL_VALID_SETTINGS_DICT["stixify"], "base_url": base_url},
    }

    with pytest.raises(ConfigValidationError):
        build_settings(settings_dict)
