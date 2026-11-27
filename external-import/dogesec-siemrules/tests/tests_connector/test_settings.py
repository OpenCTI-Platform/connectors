"""Tests of the Pydantic settings of the SIEM Rules connector."""

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
    "siemrules": {
        "api_key": "test-api-key",
    },
}

FULL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "test, connector",
        "log_level": "error",
        "duration_period": "PT12H",
    },
    "siemrules": {
        "base_url": "https://test-siemrules-url/",
        "api_key": "test-api-key",
        "detection_packs": "pack-1, pack-2",
    },
}


def build_settings_class(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    """Return a `ConnectorSettings` subclass validating `settings_dict` only.

    No environment variable nor `config.yml` file is read.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(deepcopy(settings_dict))

    return FakeConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict: dict[str, Any]) -> None:
    """`ConnectorSettings` accepts a valid configuration."""
    settings = build_settings_class(settings_dict)()

    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.siemrules, BaseConfigModel)


def test_settings_should_parse_full_input() -> None:
    """`ConnectorSettings` exposes every given value with its expected type."""
    settings = build_settings_class(FULL_VALID_SETTINGS_DICT)()

    assert settings.connector.id == "connector-id"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["test", "connector"]
    assert settings.connector.duration_period == timedelta(hours=12)
    assert str(settings.siemrules.base_url) == "https://test-siemrules-url/"
    assert settings.siemrules.api_key.get_secret_value() == "test-api-key"
    assert settings.siemrules.detection_packs == ["pack-1", "pack-2"]


def test_settings_should_apply_defaults() -> None:
    """The minimal configuration yields the documented defaults."""
    settings = build_settings_class(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.name == "SIEM Rules"
    assert settings.connector.scope == ["siemrules"]
    assert settings.connector.log_level == "error"
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert str(settings.siemrules.base_url) == "https://api.siemrules.com/"
    assert settings.siemrules.detection_packs == []


def test_settings_should_default_connector_id() -> None:
    """An empty `connector` section yields the default UUIDv4 connector id."""
    settings = build_settings_class(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.id == "1e0cf3de-6f90-488e-9af1-be4fee322f48"
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
            {**MINIMAL_VALID_SETTINGS_DICT, "connector": {"id": 123456}},
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "siemrules": {"detection_packs": "pack-1"},
            },
            id="missing_siemrules_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(
    settings_dict: dict[str, Any],
) -> None:
    """`ConnectorSettings` raises `ConfigValidationError` on an invalid configuration."""
    with pytest.raises(ConfigValidationError) as err:
        build_settings_class(settings_dict)()

    assert "Error validating configuration" in str(err)


def test_settings_should_migrate_deprecated_interval_hours() -> None:
    """The legacy `siemrules.interval_hours` alone migrates to `duration_period`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "siemrules": {**MINIMAL_VALID_SETTINGS_DICT["siemrules"], "interval_hours": 6},
    }

    with pytest.warns(UserWarning, match="siemrules.interval_hours"):
        settings = build_settings_class(settings_dict)()

    assert settings.connector.duration_period == timedelta(hours=6)


def test_settings_should_prefer_duration_period_over_interval_hours() -> None:
    """When both are set, `connector.duration_period` wins."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"duration_period": "PT30M"},
        "siemrules": {**MINIMAL_VALID_SETTINGS_DICT["siemrules"], "interval_hours": 6},
    }

    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = build_settings_class(settings_dict)()

    assert settings.connector.duration_period == timedelta(minutes=30)


@pytest.mark.parametrize(
    "base_url",
    ["api.example.com", "ftp://api.example.com", "not a url"],
)
def test_settings_should_reject_invalid_base_url(base_url):
    """`siemrules.base_url` must be an absolute HTTP(S) URL."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "siemrules": {**MINIMAL_VALID_SETTINGS_DICT["siemrules"], "base_url": base_url},
    }

    with pytest.raises(ConfigValidationError):
        build_settings_class(settings_dict)()
