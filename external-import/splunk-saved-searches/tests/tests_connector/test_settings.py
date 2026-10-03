from datetime import timedelta
from typing import Any

import pytest
from conftest import BASE_CONFIG
from connector import ConnectorSettings
from connectors_sdk import ConfigValidationError


def _settings_with(overrides: dict[str, Any]) -> ConnectorSettings:
    config = {section: dict(values) for section, values in BASE_CONFIG.items()}
    for section, values in overrides.items():
        config.setdefault(section, {}).update(values)

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> dict[str, Any]:
            return handler(config)

    return FakeConnectorSettings()


def test_defaults():
    settings = _settings_with({})
    assert isinstance(settings, ConnectorSettings)
    config = settings.splunk_saved_searches
    assert str(config.api_url) == "https://splunk.example.com:8089/"
    assert config.token.get_secret_value() == "splunk-token"
    assert (config.app, config.owner) == ("-", "-")
    assert config.search_scope == "alerts"
    assert config.web_url is None
    assert config.import_disabled_rules is True
    assert config.page_size == 100
    assert config.verify_ssl is True
    assert config.platform_name == "Splunk"
    assert config.platform_type == "SIEM"
    assert config.tlp_level.value == "amber"
    assert settings.connector.name == "Splunk Saved Searches"
    assert settings.connector.duration_period == timedelta(hours=6)
    assert isinstance(settings.to_helper_config(), dict)


def test_overrides():
    config = _settings_with(
        {
            "splunk_saved_searches": {
                "app": "SplunkEnterpriseSecuritySuite",
                "owner": "nobody",
                "search_scope": "correlation_searches",
                "web_url": "https://splunk.example.com:8000",
                "verify_ssl": "false",
            }
        }
    ).splunk_saved_searches
    assert config.app == "SplunkEnterpriseSecuritySuite"
    assert config.search_scope == "correlation_searches"
    assert str(config.web_url) == "https://splunk.example.com:8000/"
    assert config.verify_ssl is False


@pytest.mark.parametrize("missing", ["api_url", "token"])
def test_required_fields(missing):
    with pytest.raises(ConfigValidationError):
        _settings_with({"splunk_saved_searches": {missing: None}})


@pytest.mark.parametrize(
    "field,value",
    [
        ("api_url", "not a url"),
        ("app", ""),
        ("search_scope", "reports"),
        ("page_size", 0),
        ("page_size", 10001),
        ("max_retries", -1),
        ("platform_type", "Firewall"),
        ("tlp_level", "purple"),
    ],
)
def test_invalid_values(field, value):
    with pytest.raises(ConfigValidationError):
        _settings_with({"splunk_saved_searches": {field: value}})
