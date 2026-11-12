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
    config = settings.crowdstrike_ioa_rules
    assert str(config.base_url) == "https://api.crowdstrike.com/"
    assert config.client_id == "falcon-client"
    assert config.client_secret.get_secret_value() == "falcon-secret"
    assert config.member_cid is None
    assert config.rule_group_filter is None
    assert config.check_prevention_policies is True
    assert config.import_disabled_rules is True
    assert config.page_size == 100
    assert config.platform_name == "CrowdStrike Falcon"
    assert config.platform_id is None
    assert config.platform_type == "EDR"
    assert config.tlp_level.value == "amber"
    assert settings.connector.name == "CrowdStrike Falcon Custom IOA Rules"
    assert settings.connector.duration_period == timedelta(hours=6)
    assert isinstance(settings.to_helper_config(), dict)


def test_other_cloud_and_child_cid():
    config = _settings_with(
        {
            "crowdstrike_ioa_rules": {
                "base_url": "https://api.eu-1.crowdstrike.com",
                "member_cid": "abcdef0123456789",
                "rule_group_filter": "platform:'windows'",
            }
        }
    ).crowdstrike_ioa_rules
    assert str(config.base_url) == "https://api.eu-1.crowdstrike.com/"
    assert config.member_cid == "abcdef0123456789"
    assert config.rule_group_filter == "platform:'windows'"


@pytest.mark.parametrize("missing", ["client_id", "client_secret"])
def test_required_fields(missing):
    with pytest.raises(ConfigValidationError):
        _settings_with({"crowdstrike_ioa_rules": {missing: None}})


@pytest.mark.parametrize(
    "field,value",
    [
        ("base_url", "api.crowdstrike.com"),
        ("client_id", ""),
        ("page_size", 0),
        ("page_size", 501),
        ("max_retries", -1),
        ("platform_type", "Antivirus"),
        ("platform_id", ""),
        ("tlp_level", "purple"),
    ],
)
def test_invalid_values(field, value):
    with pytest.raises(ConfigValidationError):
        _settings_with({"crowdstrike_ioa_rules": {field: value}})
