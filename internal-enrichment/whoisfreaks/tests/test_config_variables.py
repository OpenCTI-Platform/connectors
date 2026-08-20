import pytest
from config_variables import ConfigVariables
from connectors_sdk import ConfigValidationError


@pytest.fixture
def valid_env(monkeypatch):
    """Provides a complete set of valid environment variables."""
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token-uuid-1234",
        "CONNECTOR_ID": "whoisfreaks-connector-id-1234",
        "CONNECTOR_NAME": "WhoisFreaks",
        "CONNECTOR_SCOPE": "Domain-Name,IPv4-Addr,IPv6-Addr",
        "CONNECTOR_LOG_LEVEL": "info",
        "WHOISFREAKS_API_KEY": "test_whoisfreaks_api_key_xyz",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env


def test_config_variables_success(valid_env):
    """Tests successful instantiation when all environment variables are present."""
    config = ConfigVariables()
    assert str(config.opencti_url).rstrip("/") == "http://localhost:8080"
    assert config.opencti_token == "test-token-uuid-1234"
    assert config.whoisfreaks_api_key == "test_whoisfreaks_api_key_xyz"


def test_config_variables_missing_opencti_url(valid_env, monkeypatch):
    """Executes validation failure lines when OPENCTI_URL is missing/invalid."""
    monkeypatch.delenv("OPENCTI_URL")
    with pytest.raises((ConfigValidationError, Exception)):
        ConfigVariables()


def test_config_variables_missing_opencti_token(valid_env, monkeypatch):
    """Executes validation failure lines when OPENCTI_TOKEN is missing/invalid."""
    monkeypatch.delenv("OPENCTI_TOKEN")
    with pytest.raises((ConfigValidationError, Exception)):
        ConfigVariables()


def test_config_variables_missing_api_key(valid_env, monkeypatch):
    """Executes validation failure lines when WHOISFREAKS_API_KEY is missing/invalid."""
    monkeypatch.delenv("WHOISFREAKS_API_KEY")
    with pytest.raises((ConfigValidationError, Exception)):
        ConfigVariables()


def test_config_variables_empty_values(valid_env, monkeypatch):
    """Executes validation checks when required variables are empty strings."""
    monkeypatch.setenv("WHOISFREAKS_API_KEY", "")
    with pytest.raises((ConfigValidationError, Exception)):
        ConfigVariables()


def test_config_variables_missing_connector_id(valid_env, monkeypatch):
    """Executes validation failure lines when CONNECTOR_ID is missing."""
    monkeypatch.delenv("CONNECTOR_ID")
    with pytest.raises((ConfigValidationError, Exception)):
        ConfigVariables()
