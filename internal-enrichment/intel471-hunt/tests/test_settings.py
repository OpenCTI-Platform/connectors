"""Configuration tests: valid input, defaults, and missing required fields."""

from __future__ import annotations

import pytest
from connectors_sdk import ConfigValidationError
from src.settings import ConnectorSettings

REQUIRED_ENV = {
    "OPENCTI_URL": "http://localhost:8080",
    "OPENCTI_TOKEN": "token",
    "CONNECTOR_ID": "11111111-1111-1111-1111-111111111111",
    "HUNTER_API_KEY": "secret",
}


@pytest.fixture
def env(monkeypatch):
    """Start from a clean slate so the host environment can't leak in."""
    for key in list(REQUIRED_ENV) + [
        "CONNECTOR_NAME",
        "CONNECTOR_SCOPE",
        "CONNECTOR_AUTO",
        "CONNECTOR_LOG_LEVEL",
        "HUNTER_API_BASE_URL",
        "HUNTER_UI_BASE_URL",
        "HUNTER_INDEXES",
        "HUNTER_REQUEST_TIMEOUT_SECONDS",
        "HUNTER_MAX_RESULTS_PER_QUERY",
        "HUNTER_CACHE_PATH",
        "HUNTER_CACHE_TTL_HOURS",
        "HUNTER_MAX_TLP",
    ]:
        monkeypatch.delenv(key, raising=False)
    for key, value in REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def test_settings_load_with_required_values(env):
    settings = ConnectorSettings()

    assert settings.opencti.token.get_secret_value() == "token"
    assert settings.connector.id == REQUIRED_ENV["CONNECTOR_ID"]
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.hunter.api_key.get_secret_value() == "secret"


def test_settings_defaults(env):
    settings = ConnectorSettings()

    assert settings.connector.name == "Intel 471 Hunter"
    assert settings.connector.auto is False
    assert settings.hunter.indexes == "cyborg_usecases"
    assert settings.hunter.request_timeout_seconds == 30
    assert settings.hunter.max_results_per_query == 100
    assert settings.hunter.cache_ttl_hours == 24
    assert settings.hunter.max_tlp == "TLP:AMBER"
    assert str(settings.hunter.api_base_url).startswith(
        "https://api.hunter.cyborgsecurity.io"
    )
    # The scope must carry the emitted types, or OpenCTI drops them.
    for emitted in ("Report", "Indicator", "Note"):
        assert emitted in settings.connector.scope


def test_environment_overrides_defaults(env):
    env.setenv("HUNTER_INDEXES", "other_index")
    env.setenv("HUNTER_MAX_RESULTS_PER_QUERY", "5")
    env.setenv("CONNECTOR_SCOPE", "Report,Indicator")

    settings = ConnectorSettings()

    assert settings.hunter.indexes == "other_index"
    assert settings.hunter.max_results_per_query == 5
    assert settings.connector.scope == ["Report", "Indicator"]


def test_missing_required_field_raises(env):
    env.delenv("HUNTER_API_KEY")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_missing_opencti_token_raises(env):
    env.delenv("OPENCTI_TOKEN")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_invalid_value_raises(env):
    env.setenv("HUNTER_MAX_TLP", "TLP:PURPLE")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_to_helper_config_is_pycti_shaped(env):
    settings = ConnectorSettings()

    helper_config = settings.to_helper_config()

    # pycti expects a plain secret and a comma-separated scope string.
    assert helper_config["opencti"]["token"] == "token"
    assert isinstance(helper_config["connector"]["scope"], str)
    assert "Report" in helper_config["connector"]["scope"]
