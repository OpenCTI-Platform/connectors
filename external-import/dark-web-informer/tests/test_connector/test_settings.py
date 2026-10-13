"""Configuration validation tests."""

import pytest


@pytest.fixture(autouse=True)
def _env(mock_env):
    """Apply the shared environment fixture to every test in this module."""


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


@pytest.mark.parametrize(
    "missing_var",
    ["OPENCTI_URL", "OPENCTI_TOKEN", "CONNECTOR_ID", "DARK_WEB_INFORMER_API_KEY"],
)
def test_missing_required_setting_raises(monkeypatch, missing_var):
    from connector.settings import ConnectorSettings
    from connectors_sdk import ConfigValidationError

    monkeypatch.delenv(missing_var, raising=False)

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()
