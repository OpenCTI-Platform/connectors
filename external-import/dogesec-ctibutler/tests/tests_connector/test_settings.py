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
    "ctibutler": {
        "api_key": "test-api-key",
        "knowledgebases": "attack-enterprise,capec",
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Instantiate `ConnectorSettings` from a dict instead of env vars or config.yml."""

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
                    "id": "connector-id",
                    "name": "CTIButler",
                    "scope": "ctibutler",
                    "log_level": "info",
                    "duration_period": "P7D",
                },
                "ctibutler": {
                    "base_url": "https://api.ctibutler.com/",
                    "api_key": "test-api-key",
                    "knowledgebases": "attack-enterprise,capec",
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
    assert isinstance(settings.ctibutler, BaseConfigModel)
    assert settings.ctibutler.api_key.get_secret_value() == "test-api-key"
    assert settings.ctibutler.knowledgebases == "attack-enterprise,capec"


def test_settings_should_apply_defaults():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "CTIButler"
    assert settings.connector.scope == ["ctibutler"]
    assert settings.connector.log_level == "error"
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period == timedelta(days=7)
    assert str(settings.ctibutler.base_url) == "https://api.ctibutler.com/"


def test_settings_should_default_connector_id():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == "15bf64d8-ff5f-4a6c-95cb-19edfefea75c"
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "opencti": {"url": "http://localhost:8080"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"id": 12345},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "ctibutler": {"knowledgebases": "attack-enterprise,capec"},
            },
            id="missing_ctibutler_api_key",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "ctibutler": {"api_key": "test-api-key"},
            },
            id="missing_ctibutler_knowledgebases",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)
    assert "Error validating configuration" in str(err)


def test_settings_should_migrate_deprecated_interval_days():
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "ctibutler": {
            **MINIMAL_VALID_SETTINGS_DICT["ctibutler"],
            "interval_days": "3",
        },
    }

    with pytest.warns(UserWarning, match="ctibutler.interval_days"):
        settings = build_settings(settings_dict)

    assert settings.connector.duration_period == timedelta(days=3)


def test_settings_should_prefer_duration_period_over_interval_days():
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"duration_period": "PT12H"},
        "ctibutler": {
            **MINIMAL_VALID_SETTINGS_DICT["ctibutler"],
            "interval_days": "3",
        },
    }

    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = build_settings(settings_dict)

    assert settings.connector.duration_period == timedelta(hours=12)


@pytest.mark.parametrize(
    "base_url",
    ["api.example.com", "ftp://api.example.com", "not a url"],
)
def test_settings_should_reject_invalid_base_url(base_url):
    """`ctibutler.base_url` must be an absolute HTTP(S) URL."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "ctibutler": {**MINIMAL_VALID_SETTINGS_DICT["ctibutler"], "base_url": base_url},
    }

    with pytest.raises(ConfigValidationError):
        build_settings(settings_dict)
