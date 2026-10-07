from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def fake_settings(settings_dict: dict) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


MINIMAL = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {"id": "connector-id"},
    "dnslytics": {"api_key": "test-api-key"},
}

# What XTM Composer provides from the catalog form: no CONNECTOR_ID
COMPOSER = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "dnslytics": {"api_key": "test-api-key"},
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "DNSlytics",
                    "scope": "Indicator",
                    "log_level": "error",
                    "auto": False,
                    "max_tlp": "TLP:AMBER",
                },
                "dnslytics": {
                    "api_key": "test-api-key",
                    "resolve_hosting": False,
                    "output_tlp_level": "green",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(MINIMAL, id="minimal_valid_settings_dict"),
        pytest.param(COMPOSER, id="composer_settings_without_connector_id"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    settings = fake_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.dnslytics, BaseConfigModel) is True


def test_settings_defaults_follow_the_rfc():
    settings = fake_settings(MINIMAL)

    assert settings.connector.name == "DNSlytics"
    assert settings.connector.scope == ["Indicator"]
    assert settings.connector.auto is False
    assert settings.dnslytics.resolve_hosting is True
    assert settings.connector.max_tlp == "TLP:GREEN"
    assert settings.dnslytics.output_tlp_level == "clear"
    assert str(settings.dnslytics.api_base_url) == "https://api.dnslytics.net/"


def test_max_tlp_default_is_green():
    settings = fake_settings(MINIMAL)

    assert settings.connector.max_tlp == "TLP:GREEN"


def test_deprecated_dnslytics_max_tlp_level_is_migrated_to_connector_max_tlp():
    settings_dict = {
        **MINIMAL,
        "dnslytics": {"api_key": "test-api-key", "max_tlp_level": "red"},
    }

    with pytest.warns(UserWarning, match="dnslytics.max_tlp_level"):
        settings = fake_settings(settings_dict)

    assert settings.connector.max_tlp == "TLP:RED"


def test_connector_id_has_a_stable_uuid_default():
    import uuid

    first = fake_settings(COMPOSER).connector.id
    second = fake_settings(COMPOSER).connector.id

    assert first == second
    assert uuid.UUID(first).version == 4


def test_api_key_is_never_shown():
    settings = fake_settings(MINIMAL)

    assert "test-api-key" not in repr(settings)
    assert settings.dnslytics.api_key.get_secret_value() == "test-api-key"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {**MINIMAL, "dnslytics": {}},
            id="missing_api_key",
        ),
        pytest.param(
            {**MINIMAL, "connector": {"id": "connector-id", "max_tlp": "purple"}},
            id="invalid_max_tlp",
        ),
        pytest.param(
            {**MINIMAL, "opencti": {"url": "http://localhost:PORT", "token": "t"}},
            id="invalid_opencti_url",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        fake_settings(settings_dict)
    assert str("Error validating configuration") in str(err)
