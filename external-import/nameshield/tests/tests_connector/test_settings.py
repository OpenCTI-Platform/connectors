from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import ConfigValidationError
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "nameshield": {
        "auth_bearer": "test-bearer",
    },
}

FULL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "NameShield",
        "scope": "NameShield",
        "log_level": "error",
        "duration_period": "P1D",
    },
    "nameshield": {
        "auth_bearer": "test-bearer",
        "server": "api.nameshield.net",
        "api_version": "v1",
        "api_endpoint": "registrar",
        "url_list": "https://{server}/{api_endpoint}/{api_version}/domains",
        "url_domain": "https://{server}/{api_endpoint}/{api_version}/domains/{domain}",
        "domain_limit": 500,
        "marking": "TLP:AMBER",
        "link_to_identities": "identity--8a4a3a9a-2d3c-5b46-9a42-6f6c0c1b5f3e",
    },
}


def _settings_class(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """Valid configurations (full and minimal) MUST be accepted."""
    settings = _settings_class(settings_dict)()

    assert settings.opencti.token.get_secret_value() == "test-token"
    assert settings.nameshield.auth_bearer.get_secret_value() == "test-bearer"
    assert isinstance(settings.to_helper_config(), dict)


def test_settings_should_apply_defaults():
    """Optional fields MUST fall back on the legacy defaults."""
    settings = _settings_class(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.name == "NameShield"
    assert settings.connector.scope == ["NameShield"]
    assert settings.connector.duration_period == timedelta(hours=168)
    assert settings.nameshield.server == "api.nameshield.net"
    assert settings.nameshield.api_version == "v1"
    assert settings.nameshield.api_endpoint == "registrar"
    assert (
        settings.nameshield.url_list
        == "https://{server}/{api_endpoint}/{api_version}/domains"
    )
    assert (
        settings.nameshield.url_domain
        == "https://{server}/{api_endpoint}/{api_version}/domains/{domain}"
    )
    assert settings.nameshield.domain_limit == 10000
    assert settings.nameshield.marking == "TLP:GREEN"
    assert settings.nameshield.link_to_identities == ""


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = _settings_class({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})()

    assert settings.connector.id == "46ae8578-037f-49fc-b68c-f803f1f0d86e"
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
            {**MINIMAL_VALID_SETTINGS_DICT, "connector": {"id": 123}},
            id="invalid_connector_id",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "nameshield": {}},
            id="missing_nameshield_auth_bearer",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """Invalid configurations MUST raise a `ConfigValidationError`."""
    with pytest.raises(ConfigValidationError) as err:
        _settings_class(settings_dict)()

    assert "Error validating configuration" in str(err.value)


def test_settings_should_migrate_interval_to_duration_period():
    """The deprecated `interval` (hours) MUST become `connector.duration_period`."""
    with pytest.warns(UserWarning, match="nameshield.interval"):
        settings = _settings_class(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "nameshield": {"auth_bearer": "test-bearer", "interval": 24},
            }
        )()

    assert settings.connector.duration_period == timedelta(hours=24)


def test_settings_should_prefer_duration_period_when_interval_is_also_set():
    """`connector.duration_period` MUST win over the deprecated `interval`."""
    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = _settings_class(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"duration_period": "PT12H"},
                "nameshield": {"auth_bearer": "test-bearer", "interval": 24},
            }
        )()

    assert settings.connector.duration_period == timedelta(hours=12)


def test_settings_should_migrate_marking_definition_to_marking():
    """The former config.yml key `marking_definition` MUST become `marking`."""
    with pytest.warns(UserWarning, match="nameshield.marking_definition"):
        settings = _settings_class(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "nameshield": {
                    "auth_bearer": "test-bearer",
                    "marking_definition": "TLP:RED",
                },
            }
        )()

    assert settings.nameshield.marking == "TLP:RED"


def test_settings_should_prefer_marking_when_marking_definition_is_also_set():
    """`marking` MUST win over the deprecated `marking_definition`."""
    with pytest.warns(UserWarning, match="Using only 'nameshield.marking'"):
        settings = _settings_class(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "nameshield": {
                    "auth_bearer": "test-bearer",
                    "marking": "TLP:AMBER",
                    "marking_definition": "TLP:RED",
                },
            }
        )()

    assert settings.nameshield.marking == "TLP:AMBER"
