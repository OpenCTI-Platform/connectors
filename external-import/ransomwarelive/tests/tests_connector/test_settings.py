from datetime import datetime

import pytest
from connectors_sdk import ConfigValidationError
from ransomwarelive.settings import ConnectorSettings


def _set_env(monkeypatch, env: dict[str, str]) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize(
    "env",
    [
        pytest.param(
            {
                "OPENCTI_URL": "http://localhost:8080",
                "OPENCTI_TOKEN": "test-token",
                "CONNECTOR_ID": "connector-id",
                "CONNECTOR_NAME": "Test Connector",
                "CONNECTOR_SCOPE": "identity,report",
                "CONNECTOR_LOG_LEVEL": "error",
                "CONNECTOR_DURATION_PERIOD": "PT5M",
                "RANSOMWARELIVE_API_BASE_URL": "https://api.ransomware.live/v2",
            },
            id="full_valid_settings",
        ),
        pytest.param(
            {
                "OPENCTI_URL": "http://localhost:8080",
                "OPENCTI_TOKEN": "test-token",
                "CONNECTOR_ID": "connector-id",
                "CONNECTOR_SCOPE": "identity,report",
                "RANSOMWARELIVE_API_BASE_URL": "https://api-pro.ransomware.live",
                "RANSOMWARELIVE_API_KEY": "test-api-key",
            },
            id="minimal_valid_settings",
        ),
    ],
)
def test_settings_should_accept_valid_input(monkeypatch, env):
    # Given
    _set_env(monkeypatch, env)

    # When
    settings = ConnectorSettings()

    # Then
    assert settings.opencti.url
    assert settings.connector.id
    assert settings.ransomwarelive.api_base_url


@pytest.mark.parametrize(
    "env",
    [
        pytest.param(
            {},
            id="empty_settings",
        ),
        pytest.param(
            {
                "OPENCTI_URL": "http://localhost:PORT",
                "OPENCTI_TOKEN": "test-token",
                "CONNECTOR_ID": "connector-id",
                "CONNECTOR_NAME": "Test Connector",
                "CONNECTOR_SCOPE": "identity,report",
                "RANSOMWARELIVE_API_BASE_URL": "https://api.ransomware.live/v2",
            },
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "OPENCTI_URL": "http://localhost:8080",
                "CONNECTOR_SCOPE": "identity,report",
                "RANSOMWARELIVE_API_BASE_URL": "https://api.ransomware.live/v2",
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "OPENCTI_URL": "http://localhost:8080",
                "OPENCTI_TOKEN": "test-token",
                "CONNECTOR_ID": "connector-id",
                "CONNECTOR_SCOPE": "identity,report",
                "RANSOMWARELIVE_API_BASE_URL": "https://api-pro.ransomware.live/v2",
            },
            id="invalid_api_base_url_literal",
        ),
        pytest.param(
            {
                "OPENCTI_URL": "http://localhost:8080",
                "OPENCTI_TOKEN": "test-token",
                "CONNECTOR_ID": "connector-id",
                "CONNECTOR_SCOPE": "identity,report",
                "RANSOMWARELIVE_API_BASE_URL": "https://api-pro.ransomware.live",
            },
            id="missing_api_key_for_pro",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(monkeypatch, env):
    # Given
    _set_env(monkeypatch, env)

    # When / Then
    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_settings_should_accept_yyyymm_history_start_year(monkeypatch):
    # Given
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token",
        "CONNECTOR_ID": "connector-id",
        "CONNECTOR_SCOPE": "identity,report",
        "RANSOMWARELIVE_HISTORY_START_YEAR": f"{datetime.now().year:04d}01",
        "RANSOMWARELIVE_API_BASE_URL": "https://api.ransomware.live/v2",
    }
    _set_env(monkeypatch, env)

    # When
    settings = ConnectorSettings()

    # Then
    assert settings.ransomwarelive.history_start_year > 0


def test_settings_should_migrate_deprecated_connector_prefix(monkeypatch):
    # Given
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token",
        "CONNECTOR_SCOPE": "identity,report",
        "CONNECTOR_PULL_HISTORY": "true",
        "RANSOMWARELIVE_API_BASE_URL": "https://api.ransomware.live/v2",
    }
    _set_env(monkeypatch, env)

    # When
    settings = ConnectorSettings()

    # Then
    assert settings.ransomwarelive.pull_history is True
