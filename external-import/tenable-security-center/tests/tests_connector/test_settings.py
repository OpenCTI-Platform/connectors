# pragma: no cover  # do not test coverage of tests...
# isort: skip_file
# type: ignore
"""Provide unit tests for the connector's Pydantic settings."""

from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError

from tenable_security_center.settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
    },
    "tsc": {
        "api_base_url": "https://tenable-security-center.test",
        "api_access_key": "test-access-key",
        "api_secret_key": "test-secret-key",
        "export_since": "2024-11-18T12:00:00Z",
    },
}

FULL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "vulnerability",
        "log_level": "error",
        "duration_period": "PT12H",
    },
    "tsc": {
        "api_base_url": "https://tenable-security-center.test",
        "api_access_key": "test-access-key",
        "api_secret_key": "test-secret-key",
        "api_timeout": 60,
        "api_backoff": 10,
        "api_retries": 5,
        "export_since": "2024-11-18T12:00:00Z",
        "severity_min_level": "critical",
        "process_systems_without_vulnerabilities": True,
        "marking_definition": "TLP:AMBER",
        "number_threads": 4,
    },
}


def _fake_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Instantiate `ConnectorSettings` from a given dict instead of env/config vars."""

    class FakeConnectorSettings(ConnectorSettings):
        """Subclass of `ConnectorSettings` for testing purpose.

        It overrides `BaseConnectorSettings._load_config_dict` to return a fake config dict.
        """

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
    """Test that `ConnectorSettings` accepts valid input.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    settings = _fake_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.tsc, BaseConfigModel) is True


def test_settings_should_apply_optional_defaults():
    """Test that the optional variables fall back on the connector's documented defaults."""
    settings = _fake_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Tenable Security Center"
    assert settings.connector.scope == ["vulnerability"]
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period.total_seconds() == 12 * 3600
    assert settings.tsc.api_timeout == 30
    assert settings.tsc.api_backoff == 5
    assert settings.tsc.api_retries == 3
    assert settings.tsc.severity_min_level == "high"
    assert settings.tsc.process_systems_without_vulnerabilities is False
    assert settings.tsc.marking_definition == "TLP:CLEAR"
    assert settings.tsc.number_threads == 1


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = _fake_settings({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    assert settings.connector.id == "a9e6fb3a-6b33-4a1e-a526-54e9d001f184"
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "opencti": {"url": "http://localhost:8080"},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"id": 123456},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "tsc": {
                    **MINIMAL_VALID_SETTINGS_DICT["tsc"],
                    "severity_min_level": "unknown",
                },
            },
            "tsc.severity_min_level",
            id="invalid_severity_min_level",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "tsc": {
                    **MINIMAL_VALID_SETTINGS_DICT["tsc"],
                    "marking_definition": "TLP:PURPLE",
                },
            },
            "tsc.marking_definition",
            id="invalid_marking_definition",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "tsc": {
                    key: value
                    for key, value in MINIMAL_VALID_SETTINGS_DICT["tsc"].items()
                    if key != "api_secret_key"
                },
            },
            "tsc.api_secret_key",
            id="missing_tsc_api_secret_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """Test that `ConnectorSettings` raises on invalid input.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The name of the invalid field (for test readability only)
    """
    with pytest.raises(ConfigValidationError) as error:
        _fake_settings(settings_dict)

    assert "Error validating configuration" in str(error.value)
