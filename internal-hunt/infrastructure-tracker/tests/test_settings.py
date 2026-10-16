import pytest
from conftest import make_settings
from connectors_sdk import ConfigValidationError
from infrastructure_tracker import ConnectorSettings


def test_settings_load_from_the_environment(monkeypatch):
    # Given the configuration in environment variables
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "connector-id")
    monkeypatch.setenv("INFRASTRUCTURE_TRACKER_URLSCAN_API_KEY", "urlscan-key")
    monkeypatch.setenv("INFRASTRUCTURE_TRACKER_INTERNETDB_MAX_LOOKUPS", "5")

    # When the settings load
    settings = ConnectorSettings()

    # Then the urlscan.io source is configured
    config = settings.infrastructure_tracker
    assert config.sources == ["urlscan"]
    assert config.urlscan_api_key.get_secret_value() == "urlscan-key"
    assert config.internetdb_max_lookups == 5


def test_settings_defaults():
    # Given only a Censys token
    settings = make_settings()

    # Then the connector targets the internet platform with Censys only
    assert settings.connector.scope == ["internet"]
    assert settings.connector.name == "Infrastructure Tracker"
    assert settings.connector.security_platform_name is None
    config = settings.infrastructure_tracker
    assert config.sources == ["censys"]
    assert str(config.censys_api_url) == "https://api.platform.censys.io/"
    assert config.internetdb_max_lookups == 25
    assert config.create_certificates is True


def test_settings_lists_the_configured_sources_in_query_order():
    # Given every source key, one of them blank
    settings = make_settings(
        {
            "infrastructure_tracker": {
                "cymru_scout_api_key": "scout",
                "urlscan_api_key": "urlscan",
                "silentpush_api_key": "  ",
            }
        }
    )

    # Then the blank key disables its source
    assert settings.infrastructure_tracker.sources == [
        "censys",
        "urlscan",
        "cymru_scout",
    ]


def test_settings_require_a_source():
    # Given no source key
    with pytest.raises(ConfigValidationError):
        make_settings({"infrastructure_tracker": {"censys_token": ""}})


def test_settings_reject_a_security_platform_for_the_internet():
    # Given a Security Platform name, meaningless on the internet platform
    with pytest.raises(ConfigValidationError):
        make_settings({"connector": {"security_platform_name": "Censys"}})


@pytest.mark.parametrize("lookups", [-1, 1001])
def test_settings_bound_the_internetdb_lookups(lookups):
    with pytest.raises(ConfigValidationError):
        make_settings({"infrastructure_tracker": {"internetdb_max_lookups": lookups}})
