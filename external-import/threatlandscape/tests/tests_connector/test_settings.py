import pytest
from connector.settings import ConnectorSettings
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import ValidationError

_CONFIG_ERROR = (ValidationError, ConfigValidationError)


def _minimal_env(overrides: dict = None) -> dict:
    """Return the minimum env vars needed to build a valid ConnectorSettings."""
    base = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token",
        "CONNECTOR_ID": "00000000-0000-0000-0000-000000000001",
        "CONNECTOR_SCOPE": "indicator,report",
        "THREATLANDSCAPE_API_KEY": "test-api-key",
        "THREATLANDSCAPE_FEED": "intelligence",
    }
    if overrides:
        base.update(overrides)
    return base


def test_valid_minimal_config(monkeypatch):
    """Connector starts with only the required fields set."""
    for key, val in _minimal_env().items():
        monkeypatch.setenv(key, val)

    settings = ConnectorSettings()

    assert str(settings.threatlandscape.api_base_url).startswith(
        "https://api.threatlandscape.io"
    )
    assert settings.threatlandscape.api_key == "test-api-key"
    assert settings.threatlandscape.import_since.days == 30
    assert settings.threatlandscape.feed == "intelligence"
    assert settings.threatlandscape.page_size == 100


def test_default_connector_name(monkeypatch):
    """Connector name defaults to 'Threat Landscape'."""
    for key, val in _minimal_env().items():
        monkeypatch.setenv(key, val)

    settings = ConnectorSettings()
    assert settings.connector.name == "Threat Landscape"


def test_custom_import_since(monkeypatch):
    """import_since can be overridden via environment variable."""
    env = _minimal_env({"THREATLANDSCAPE_IMPORT_SINCE": "P7D"})
    for key, val in env.items():
        monkeypatch.setenv(key, val)

    settings = ConnectorSettings()
    assert settings.threatlandscape.import_since.days == 7


def test_feed_intelligence_osint(monkeypatch):
    """feed accepts 'intelligence-osint'."""
    env = _minimal_env({"THREATLANDSCAPE_FEED": "intelligence-osint"})
    for key, val in env.items():
        monkeypatch.setenv(key, val)

    settings = ConnectorSettings()
    assert settings.threatlandscape.feed == "intelligence-osint"


def test_feed_intelligence_darknet(monkeypatch):
    """feed accepts 'intelligence-darknet'."""
    env = _minimal_env({"THREATLANDSCAPE_FEED": "intelligence-darknet"})
    for key, val in env.items():
        monkeypatch.setenv(key, val)

    settings = ConnectorSettings()
    assert settings.threatlandscape.feed == "intelligence-darknet"


def test_feed_ioc(monkeypatch):
    """feed accepts 'ioc'."""
    env = _minimal_env({"THREATLANDSCAPE_FEED": "ioc"})
    for key, val in env.items():
        monkeypatch.setenv(key, val)

    settings = ConnectorSettings()
    assert settings.threatlandscape.feed == "ioc"


def test_invalid_feed_raises(monkeypatch):
    """An unrecognised feed value raises a ValidationError."""
    env = _minimal_env({"THREATLANDSCAPE_FEED": "unknown"})
    for key, val in env.items():
        monkeypatch.setenv(key, val)

    with pytest.raises(_CONFIG_ERROR):
        ConnectorSettings()


def test_missing_feed_raises(monkeypatch):
    """Omitting THREATLANDSCAPE_FEED raises a ValidationError."""
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token",
        "CONNECTOR_ID": "00000000-0000-0000-0000-000000000001",
        "CONNECTOR_SCOPE": "indicator,report",
        "THREATLANDSCAPE_API_KEY": "test-api-key",
    }
    for key, val in env.items():
        monkeypatch.setenv(key, val)

    with pytest.raises(_CONFIG_ERROR):
        ConnectorSettings()


def test_page_size_bounds(monkeypatch):
    """page_size must be between 1 and 1000."""
    for bad_value in ("0", "1001"):
        env = _minimal_env({"THREATLANDSCAPE_PAGE_SIZE": bad_value})
        for key, val in env.items():
            monkeypatch.setenv(key, val)

        with pytest.raises(_CONFIG_ERROR):
            ConnectorSettings()


def test_missing_api_key_raises(monkeypatch):
    """Omitting the API key raises a ValidationError."""
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token",
        "CONNECTOR_ID": "00000000-0000-0000-0000-000000000001",
    }
    for key, val in env.items():
        monkeypatch.setenv(key, val)

    with pytest.raises(_CONFIG_ERROR):
        ConnectorSettings()
