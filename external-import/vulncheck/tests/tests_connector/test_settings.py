"""Tests for connector.settings (connectors-sdk configuration).

Follows the external-import template pattern: an inline ``FakeConnectorSettings``
overrides ``_load_config_dict`` to feed a fake-but-typed config dict, plus
env-driven tests for VulnCheck-specific behaviour (defaults, list parsing and
the legacy ``CONNECTOR_VULNCHECK_*`` deprecation aliases).
"""

import warnings
from datetime import timedelta
from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError

VALID = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "VulnCheck",
        "scope": "vulnerability,software",
        "log_level": "info",
        "duration_period": "PT1H",
    },
    "vulncheck": {"api_key": "test-api-key"},
}

REQUIRED_ENV = {
    "OPENCTI_URL": "http://localhost:8080",
    "OPENCTI_TOKEN": "test-token",
    "CONNECTOR_ID": "connector-id",
    "CONNECTOR_SCOPE": "vulnerability,software",
    "CONNECTOR_DURATION_PERIOD": "PT1H",
}


def _fake_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _data: Any, handler: Any) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def _set_env(monkeypatch, **extra):
    for key, value in {**REQUIRED_ENV, **extra}.items():
        monkeypatch.setenv(key, value)


def test_settings_accepts_valid_input():
    settings = _fake_settings(VALID)
    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.vulncheck, BaseConfigModel)
    assert isinstance(settings.to_helper_config(), dict)


@pytest.mark.parametrize(
    "settings_dict, case",
    [
        ({}, "empty"),
        ({**VALID, "vulncheck": {}}, "missing_api_key"),
        (
            {**VALID, "opencti": {"url": "not-a-url", "token": "t"}},
            "invalid_opencti_url",
        ),
    ],
)
def test_settings_rejects_invalid_input(settings_dict, case):
    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        _fake_settings(settings_dict)


def test_defaults(settings):
    assert str(settings.vulncheck.api_base_url) == "https://api.vulncheck.com/v3"
    assert settings.vulncheck.data_sources == ["vulncheck-kev", "nist-nvd2"]
    assert settings.vulncheck.nvd2_pull_history is False
    assert settings.vulncheck.nvd2_max_date_range == timedelta(days=120)
    assert settings.vulncheck.nvd2_last_mod_start_date is None


def test_data_sources_parsed_to_list(monkeypatch):
    _set_env(monkeypatch, VULNCHECK_API_KEY="k", VULNCHECK_DATA_SOURCES="botnets,snort")
    assert ConnectorSettings().vulncheck.data_sources == ["botnets", "snort"]


def test_new_style_env(monkeypatch):
    _set_env(
        monkeypatch,
        VULNCHECK_API_KEY="newkey",
        VULNCHECK_NVD2_MAX_DATE_RANGE="P7D",
        VULNCHECK_NVD2_PULL_HISTORY="true",
    )
    settings = ConnectorSettings()
    assert settings.vulncheck.api_key.get_secret_value() == "newkey"
    assert settings.vulncheck.nvd2_max_date_range == timedelta(days=7)
    assert settings.vulncheck.nvd2_pull_history is True


def test_legacy_env_aliases_migrate_with_warning(monkeypatch):
    _set_env(
        monkeypatch,
        CONNECTOR_VULNCHECK_API_KEY="legacykey",
        CONNECTOR_VULNCHECK_DATA_SOURCES="vulncheck-kev",
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        settings = ConnectorSettings()
        messages = [str(w.message) for w in caught]

    assert settings.vulncheck.api_key.get_secret_value() == "legacykey"
    assert settings.vulncheck.data_sources == ["vulncheck-kev"]
    assert any("vulncheck_api_key" in m for m in messages)
