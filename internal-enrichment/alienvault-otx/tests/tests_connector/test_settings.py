import os
from pathlib import Path
from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorSettings,
    ConfigValidationError,
)
from connectors_sdk.models.enums import TLPLevel
from connectors_sdk.settings._settings_loader import _SettingsLoader
from pydantic import SecretStr


def _fake_settings_class(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    """
    Build a subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return the given dict
    (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings


def test_settings_should_be_internal_enrichment_connector_settings():
    """
    Test that `ConnectorSettings` is an implementation of `BaseInternalEnrichmentConnectorSettings`
    (from `connectors-sdk`), the settings base class dedicated to `INTERNAL_ENRICHMENT` connectors.
    """
    assert (
        issubclass(ConnectorSettings, BaseInternalEnrichmentConnectorSettings) is True
    )


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
                    "scope": "IPv4-Addr, Domain-Name, Url",
                    "log_level": "error",
                    "auto": True,
                    "max_tlp": "TLP:CLEAR",
                },
                "alienvault_otx": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "alienvault_otx": {
                    "api_key": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    # Given: Valid input
    # When: We create a ConnectorSettings instance with valid input data
    settings = _fake_settings_class(settings_dict)()

    # Then: The ConnectorSettings instance should be created successfully
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.alienvault_otx, BaseConfigModel) is True


def test_settings_should_use_documented_defaults():
    """
    Test that the defaults documented in the README, `config.yml.sample` and
    `docker-compose.yml` are the ones of `ConnectorSettings`.
    """
    # Given: Only the required settings
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "alienvault_otx": {"api_key": "test-api-key"},
    }

    # When: We create a ConnectorSettings instance
    settings = _fake_settings_class(settings_dict)()

    # Then: The documented defaults apply
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.id == "0781c790-5d76-4539-b3b5-d8e6e74bc9a2"
    assert settings.connector.name == "AlienVault OTX"
    assert settings.connector.scope == ["IPv4-Addr"]
    assert settings.connector.auto is False
    assert settings.connector.max_tlp == TLPLevel.AMBER
    assert str(settings.alienvault_otx.api_base_url) == "https://otx.alienvault.com/"
    assert isinstance(settings.alienvault_otx.api_key, SecretStr)
    assert settings.alienvault_otx.api_key.get_secret_value() == "test-api-key"


def test_settings_should_load_documented_environment_variables(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """
    Test that the environment variables documented in the README are resolved by the
    real settings loader (`BaseConnectorSettings._load_config_dict` is not overridden).
    The connector location is moved to an empty temporary directory so that no real
    `config.yml` or `.env` file is read.
    """
    # Given: The documented environment variables, and no config.yml / .env file
    for name in list(os.environ):
        if name.upper().startswith(("OPENCTI_", "CONNECTOR_", "ALIENVAULT_OTX_")):
            monkeypatch.delenv(name)
    monkeypatch.setattr(
        _SettingsLoader,
        "_get_connector_main_path",
        classmethod(lambda cls: tmp_path / "src" / "main.py"),
    )
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "test-api-key")
    monkeypatch.setenv("ALIENVAULT_OTX_API_BASE_URL", "http://otx.test")
    monkeypatch.setenv("CONNECTOR_MAX_TLP", "TLP:GREEN")
    monkeypatch.setenv("CONNECTOR_AUTO", "true")
    monkeypatch.setenv("CONNECTOR_SCOPE", "IPv4-Addr,Url")

    # When: We create a ConnectorSettings instance
    settings = ConnectorSettings()

    # Then: The values come from the environment
    assert str(settings.opencti.url) == "http://localhost:8080/"
    assert settings.alienvault_otx.api_key.get_secret_value() == "test-api-key"
    assert str(settings.alienvault_otx.api_base_url) == "http://otx.test/"
    assert settings.connector.max_tlp == TLPLevel.GREEN
    assert settings.connector.auto is True
    assert settings.connector.scope == ["IPv4-Addr", "Url"]


def test_settings_should_split_the_scope():
    """Test that a comma-separated scope is parsed as a list of entity types."""
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {"scope": "IPv4-Addr,Domain-Name, Url"},
        "alienvault_otx": {"api_key": "test-api-key"},
    }

    settings = _fake_settings_class(settings_dict)()

    assert settings.connector.scope == ["IPv4-Addr", "Domain-Name", "Url"]


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "url",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "alienvault_otx": {
                    "api_key": "test-api-key",
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "alienvault_otx": {},
            },
            "alienvault_otx.api_key",
            id="missing_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "alienvault_otx": {
                    "api_key": "test-api-key",
                    "api_base_url": "not-a-url",
                },
            },
            "alienvault_otx.api_base_url",
            id="invalid_api_base_url",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {"max_tlp": "TLP:PURPLE"},
                "alienvault_otx": {
                    "api_key": "test-api-key",
                },
            },
            "connector.max_tlp",
            id="invalid_max_tlp",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The field expected to be reported as invalid
    """
    with pytest.raises(ConfigValidationError) as err:
        _fake_settings_class(settings_dict)()

    assert "Error validating configuration" in str(err.value)
    assert field_name in str(err.value.__cause__)
