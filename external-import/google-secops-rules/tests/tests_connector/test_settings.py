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
    config = settings.google_secops_rules
    assert config.project_id == "soc-project"
    assert config.project_region == "europe"
    assert config.project_instance == "3f0ac524-5ae1-4bfd-b86d-53afc953e7e6"
    assert config.client_email == "opencti@soc-project.iam.gserviceaccount.com"
    assert config.private_key_id is None
    assert str(config.token_uri) == "https://oauth2.googleapis.com/token"
    assert str(config.base_url) == "https://chronicle.googleapis.com/"
    assert config.api_version == "v1alpha"
    assert config.import_disabled_rules is True
    assert config.page_size == 1000
    assert config.request_timeout == 60
    assert config.max_retries == 5
    assert config.platform_name == "Google SecOps"
    assert config.platform_type == "SIEM"
    assert config.tlp_level.value == "amber"
    assert settings.connector.name == "Google SecOps Detection Rules"
    assert settings.connector.scope == [
        "Indicator",
        "Attack-Pattern",
        "SecurityPlatform",
    ]
    assert settings.connector.duration_period == timedelta(hours=6)
    assert isinstance(settings.to_helper_config(), dict)


def test_private_key_line_breaks_are_restored():
    key = _settings_with({}).google_secops_rules.private_key.get_secret_value()
    assert key == "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"


def test_private_key_is_not_printed():
    config = _settings_with({}).google_secops_rules
    assert "MIIE" not in repr(config)


def test_other_region_and_api_version():
    config = _settings_with(
        {
            "google_secops_rules": {
                "project_region": "europe-west2",
                "api_version": "v1",
                "private_key_id": "0123abcd",
            }
        }
    ).google_secops_rules
    assert config.project_region == "europe-west2"
    assert config.api_version == "v1"
    assert config.private_key_id == "0123abcd"


@pytest.mark.parametrize(
    "missing",
    ["project_id", "project_region", "project_instance", "client_email", "private_key"],
)
def test_required_fields(missing):
    with pytest.raises(ConfigValidationError):
        _settings_with({"google_secops_rules": {missing: None}})


@pytest.mark.parametrize(
    "field,value",
    [
        ("project_id", ""),
        ("project_region", "Europe West"),
        ("project_region", "eu/../x"),
        ("base_url", "chronicle.googleapis.com"),
        ("api_version", "v2"),
        ("page_size", 0),
        ("page_size", 1001),
        ("max_retries", -1),
        ("platform_type", "Antivirus"),
        ("tlp_level", "purple"),
    ],
)
def test_invalid_values(field, value):
    with pytest.raises(ConfigValidationError):
        _settings_with({"google_secops_rules": {field: value}})
