# -*- coding: utf-8 -*-
"""Validation tests for the OSINT Industries Pydantic settings."""

from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from osint_industries import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "osint_industries": {
        "api_key": "test-api-key",
    },
}


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
                    "name": "Test Connector",
                    "scope": "Email-Addr, Phone-Number",
                    "log_level": "error",
                    "auto": True,
                },
                "osint_industries": {
                    "api_key": "test-api-key",
                    "base_url": "https://api.osint.industries",
                    "tlp_level": "amber+strict",
                    "max_tlp": "TLP:RED",
                    "premium": True,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.osint_industries, BaseConfigModel) is True
    assert settings.connector.type == "INTERNAL_ENRICHMENT"


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "osint_industries": {"api_key": "test-api-key"},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {"id": 42},
                "osint_industries": {"api_key": "test-api-key"},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "osint_industries": {},
            },
            "osint_industries.api_key",
            id="missing_osint_industries_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "osint_industries": {
                    "api_key": "test-api-key",
                    "base_url": "not a url",
                },
            },
            "osint_industries.base_url",
            id="invalid_osint_industries_base_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "osint_industries": {
                    "api_key": "test-api-key",
                    "tlp_level": "purple",
                },
            },
            "osint_industries.tlp_level",
            id="invalid_osint_industries_tlp_level",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "osint_industries": {
                    "api_key": "test-api-key",
                    "max_tlp": "TLP:PURPLE",
                },
            },
            "osint_industries.max_tlp",
            id="invalid_osint_industries_max_tlp",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The name of the invalid field
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "cef186b0-eb77-41d4-8fc5-cc8739eafa2a"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_default_connector_section():
    """The `connector` section MUST mirror the values historically hardcoded in docker-compose."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.connector.name == "OSINT Industries"
    assert settings.connector.scope == [
        "Email-Addr",
        "Phone-Number",
        "User-Account",
        "Cryptocurrency-Wallet",
    ]
    assert settings.connector.auto is False
    assert settings.connector.log_level == "error"


def test_settings_should_default_osint_industries_section():
    """The `osint_industries` section MUST mirror the legacy `get_config_variable` defaults."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert str(settings.osint_industries.base_url) == "https://api.osint.industries/"
    assert settings.osint_industries.tlp_level == "amber+strict"
    assert settings.osint_industries.max_tlp == "TLP:AMBER"
    assert settings.osint_industries.premium is False


def test_settings_should_hide_secrets():
    """Secrets MUST be wrapped in `SecretStr` so they are not leaked when dumped."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.osint_industries.api_key.get_secret_value() == "test-api-key"
    assert settings.to_helper_config()["osint_industries"]["api_key"] == "**********"
    # The OpenCTI token is the only secret that must be exposed to `pycti`.
    assert settings.to_helper_config()["opencti"]["token"] == "test-token"


@pytest.mark.parametrize(
    "raw_value, expected",
    [
        pytest.param("true", True, id="string_true"),
        pytest.param("True", True, id="string_True"),
        pytest.param("1", True, id="string_1"),
        pytest.param("false", False, id="string_false"),
        pytest.param("no", False, id="string_no"),
        pytest.param(True, True, id="bool_true"),
    ],
)
def test_settings_should_coerce_premium_flag(raw_value, expected):
    """`OSINT_INDUSTRIES_PREMIUM` MUST be coerced to a real boolean by Pydantic."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "osint_industries": {
                        "api_key": "test-api-key",
                        "premium": raw_value,
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.osint_industries.premium is expected
