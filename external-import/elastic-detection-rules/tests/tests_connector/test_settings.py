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
    config = settings.elastic_detection_rules
    assert str(config.kibana_url) == "https://kibana.example.com:5601/"
    assert config.api_key.get_secret_value() == "ZWxhc3RpYzpzZWNyZXQ="
    assert config.space_id is None
    assert config.rule_filter is None
    assert config.import_disabled_rules is True
    assert config.page_size == 100
    assert config.max_retries == 5
    assert config.verify_ssl is True
    assert config.platform_name == "Elastic Security"
    assert config.platform_id is None
    assert config.platform_type == "SIEM"
    assert config.tlp_level.value == "amber"
    assert settings.connector.name == "Elastic Security Detection Rules"
    assert settings.connector.duration_period == timedelta(hours=6)
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert isinstance(settings.to_helper_config(), dict)


def test_overrides():
    settings = _settings_with(
        {
            "elastic_detection_rules": {
                "space_id": "soc",
                "rule_filter": 'alert.attributes.tags:"Production"',
                "import_disabled_rules": "false",
                "platform_type": "XDR",
                "tlp_level": "red",
            }
        }
    )
    config = settings.elastic_detection_rules
    assert config.space_id == "soc"
    assert config.import_disabled_rules is False
    assert config.platform_type == "XDR"
    assert config.tlp_level.value == "red"


@pytest.mark.parametrize("missing", ["kibana_url", "api_key"])
def test_required_fields(missing):
    with pytest.raises(ConfigValidationError):
        _settings_with({"elastic_detection_rules": {missing: None}})


@pytest.mark.parametrize(
    "field,value",
    [
        ("kibana_url", "not a url"),
        ("page_size", 0),
        ("page_size", 1001),
        ("request_timeout", 0),
        ("max_retries", -1),
        ("platform_type", "Firewall"),
        ("platform_id", ""),
        ("platform_name", ""),
        ("tlp_level", "purple"),
    ],
)
def test_invalid_values(field, value):
    with pytest.raises(ConfigValidationError):
        _settings_with({"elastic_detection_rules": {field: value}})
