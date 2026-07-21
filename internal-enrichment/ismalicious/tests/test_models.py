"""Tests for isMalicious connector configuration."""

from connector.models import ConfigLoader, IsMaliciousConfig
from pydantic import SecretStr


def test_ismalicious_config_default_api_url():
    config = IsMaliciousConfig(api_key=SecretStr("test-key"))
    assert config.api_url == "https://api.ismalicious.com"


def test_config_loader_from_env_uses_api_host_by_default(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "opencti-token")
    monkeypatch.setenv("ISMALICIOUS_API_KEY", "test-key")

    config = ConfigLoader.from_env()
    assert config.ismalicious.api_url == "https://api.ismalicious.com"


def test_config_loader_from_env_respects_api_url_override(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "opencti-token")
    monkeypatch.setenv("ISMALICIOUS_API_KEY", "test-key")
    monkeypatch.setenv("ISMALICIOUS_API_URL", "https://custom.example.com")

    config = ConfigLoader.from_env()
    assert config.ismalicious.api_url == "https://custom.example.com"
