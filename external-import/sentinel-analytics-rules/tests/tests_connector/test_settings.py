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
    config = settings.sentinel_analytics_rules
    assert config.client_secret.get_secret_value() == "s3cr3t"
    assert str(config.management_url) == "https://management.azure.com/"
    assert str(config.login_url) == "https://login.microsoftonline.com/"
    assert config.api_version == "2025-07-01-preview"
    assert config.import_disabled_rules is True
    assert config.max_retries == 5
    assert config.platform_name == "Microsoft Sentinel"
    assert config.platform_type == "SIEM"
    assert config.tlp_level.value == "amber"
    assert settings.connector.name == "Microsoft Sentinel Analytics Rules"
    assert settings.connector.duration_period == timedelta(hours=6)
    assert isinstance(settings.to_helper_config(), dict)


def test_sovereign_cloud_endpoints():
    config = _settings_with(
        {
            "sentinel_analytics_rules": {
                "management_url": "https://management.usgovcloudapi.net",
                "login_url": "https://login.microsoftonline.us",
                "import_disabled_rules": "false",
            }
        }
    ).sentinel_analytics_rules
    assert str(config.management_url) == "https://management.usgovcloudapi.net/"
    assert str(config.login_url) == "https://login.microsoftonline.us/"
    assert config.import_disabled_rules is False


@pytest.mark.parametrize(
    "missing",
    [
        "tenant_id",
        "client_id",
        "client_secret",
        "subscription_id",
        "resource_group",
        "workspace_name",
    ],
)
def test_required_fields(missing):
    with pytest.raises(ConfigValidationError):
        _settings_with({"sentinel_analytics_rules": {missing: None}})


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", ""),
        ("management_url", "not a url"),
        ("api_version", ""),
        ("request_timeout", 0),
        ("max_retries", -1),
        ("platform_type", "Firewall"),
        ("tlp_level", "purple"),
    ],
)
def test_invalid_values(field, value):
    with pytest.raises(ConfigValidationError):
        _settings_with({"sentinel_analytics_rules": {field: value}})
