"""Configuration validation tests."""

import pytest


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "d1c5e2a7-0b3f-4e8a-9c6d-7f2b1a4e9c30")
    monkeypatch.setenv("DARK_WEB_INFORMER_API_KEY", "test-key")


def test_settings_defaults():
    from connector.settings import ConnectorSettings

    settings = ConnectorSettings()
    cfg = settings.dark_web_informer
    assert str(cfg.base_url).startswith("https://api.darkwebinformer.com")
    assert set(cfg.sources) == {"feed", "ransomware", "iocs"}
    assert cfg.use_preview_endpoint is False
    assert cfg.preview_limit == 5000


def test_api_key_is_secret():
    from connector.settings import ConnectorSettings

    settings = ConnectorSettings()
    assert settings.dark_web_informer.api_key.get_secret_value() == "test-key"
