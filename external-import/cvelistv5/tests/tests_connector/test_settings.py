"""Tests for the cvelistV5 connector settings (manager-supported mode)."""

import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings

ROOT = Path(__file__).resolve().parents[2]

DEFAULT_CONNECTOR_ID = "4459cb70-312b-449c-941e-30a6c04b7a14"

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {},
}

FULL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "1d6c1e5a-3a42-4e43-9b33-6d1b4e1f0e5c",
        "name": "Test cvelistV5",
        "scope": "vulnerability,software",
        "log_level": "info",
        "duration_period": "PT30M",
    },
    "cvelistv5": {
        "repo_url": "https://git.example.com/mirror/cvelistV5.git",
        "repo_branch": "develop",
        "local_path": "/tmp/cvelistV5",
        "history_start_year": 2019,
    },
}


def _settings_from(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    settings = _settings_from(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.cvelistv5, BaseConfigModel)


def test_settings_should_read_every_field():
    settings = _settings_from(FULL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Test cvelistV5"
    assert settings.connector.scope == ["vulnerability", "software"]
    assert settings.connector.duration_period == timedelta(minutes=30)
    assert settings.cvelistv5.repo_url == "https://git.example.com/mirror/cvelistV5.git"
    assert settings.cvelistv5.repo_branch == "develop"
    assert settings.cvelistv5.local_path == "/tmp/cvelistV5"
    assert settings.cvelistv5.history_start_year == 2019


def test_settings_should_apply_defaults():
    settings = _settings_from(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "CVEProject cvelistV5"
    assert settings.connector.scope == ["identity", "vulnerability", "software"]
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert settings.connector.log_level == "info"
    assert settings.cvelistv5.repo_url == "https://github.com/CVEProject/cvelistV5.git"
    assert settings.cvelistv5.repo_branch == "main"
    assert settings.cvelistv5.local_path == "/opt/cvelistV5"
    assert settings.cvelistv5.history_start_year == 2024


def test_settings_should_default_connector_id():
    settings = _settings_from(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == DEFAULT_CONNECTOR_ID
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {"opencti": {"url": "http://localhost:8080"}, "connector": {}},
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
            },
            id="connector_id_as_int",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "cvelistv5": {"history_start_year": "not-a-year"},
            },
            id="history_start_year_not_an_int",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"duration_period": "PT0S"},
            },
            id="duration_period_zero",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"duration_period": "-PT1H"},
            },
            id="duration_period_negative",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        _settings_from(settings_dict)
    assert "Error validating configuration" in str(err)


def test_generated_configuration_schema_is_current():
    committed = json.loads(
        (ROOT / "__metadata__" / "connector_config_schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert committed == ConnectorSettings.config_json_schema(connector_name="cvelistv5")


def test_manifest_is_manager_supported():
    manifest = json.loads(
        (ROOT / "__metadata__" / "connector_manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["manager_supported"] is True
