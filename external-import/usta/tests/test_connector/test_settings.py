"""Unit tests for USTA connector settings."""

# pylint: disable=missing-function-docstring,missing-class-docstring,unsupported-membership-test,too-few-public-methods

from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connector.settings import (
    ConnectorSettings,
    ExternalImportConnectorConfig,
    UstaConfig,
)
from connectors_sdk import BaseConfigModel, ConfigValidationError

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {},
    "usta": {"api_key": "test-api-key"},
}

FULL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "12345678-1234-1234-1234-123456789012",
        "name": "Test USTA",
        "scope": "indicator, report",
        "log_level": "info",
        "duration_period": "PT30M",
    },
    "usta": {
        "api_base_url": "https://usta.prodaft.com",
        "api_key": "test-api-key",
        "import_start_date": "P90D",
        "page_size": 100,
        "import_malicious_urls": True,
        "import_phishing_sites": True,
        "import_malware_hashes": True,
        "import_compromised_credentials": True,
        "import_credit_cards": True,
        "import_deep_sight_tickets": True,
        "store_credential_password": False,
        "tlp_level": "red",
        "confidence_level": 99,
    },
}


def _fake_settings(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    """
    Build a `ConnectorSettings` subclass overriding `BaseConnectorSettings._load_config_dict`
    so that the given dict is used instead of the env/config vars parsed from
    `config.yml`, `.env` or environment variables.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings


class TestUstaConfig:
    def test_default_page_size(self):
        assert UstaConfig(api_key="k").page_size == 100

    def test_default_import_start_date(self):
        assert UstaConfig(api_key="k").import_start_date == timedelta(days=90)

    def test_default_tlp(self):
        assert UstaConfig(api_key="k").tlp_level == "red"

    def test_default_confidence(self):
        assert UstaConfig(api_key="k").confidence_level == 99

    def test_all_feeds_enabled(self):
        c = UstaConfig(api_key="k")
        assert c.import_malicious_urls is True
        assert c.import_phishing_sites is True
        assert c.import_malware_hashes is True
        assert c.import_compromised_credentials is True
        assert c.import_credit_cards is True
        assert c.import_deep_sight_tickets is True

    def test_store_credential_password_defaults_false(self):
        assert UstaConfig(api_key="k").store_credential_password is False

    def test_store_credential_password_can_be_enabled(self):
        assert (
            UstaConfig(
                api_key="k", store_credential_password=True
            ).store_credential_password
            is True
        )

    def test_invalid_confidence(self):
        with pytest.raises(Exception):
            UstaConfig(api_key="k", confidence_level=150)

    def test_invalid_tlp(self):
        with pytest.raises(Exception):
            UstaConfig(api_key="k", tlp_level="purple")

    def test_default_api_base_url(self):
        c = UstaConfig(api_key="k")
        assert "usta.prodaft.com" in str(c.api_base_url)

    def test_api_key_is_a_secret(self):
        c = UstaConfig(api_key="super-secret")
        assert "super-secret" not in str(c.api_key)
        assert c.api_key.get_secret_value() == "super-secret"


class TestExternalImportConnectorConfig:
    def test_default_name(self):
        assert ExternalImportConnectorConfig(id="1234").name == "USTA"

    def test_default_duration(self):
        assert ExternalImportConnectorConfig(id="1234").duration_period == timedelta(
            minutes=30
        )

    def test_default_scope(self):
        c = ExternalImportConnectorConfig(id="1234")
        assert "indicator" in c.scope
        assert "incident" in c.scope
        assert "user-account" in c.scope
        assert "report" in c.scope
        assert "threat-actor" in c.scope

    def test_type_is_external_import(self):
        assert ExternalImportConnectorConfig(id="1234").type == "EXTERNAL_IMPORT"

    def test_scope_accepts_comma_separated_string(self):
        c = ExternalImportConnectorConfig(id="1234", scope="indicator, report")
        assert c.scope == ["indicator", "report"]


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`)
    MUST accept valid input.
    """
    settings = _fake_settings(settings_dict)()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.usta, BaseConfigModel) is True
    assert settings.usta.api_key.get_secret_value() == "test-api-key"


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {**FULL_VALID_SETTINGS_DICT, "opencti": {"url": "http://localhost:8080"}},
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **FULL_VALID_SETTINGS_DICT,
                "connector": {**FULL_VALID_SETTINGS_DICT["connector"], "id": 123456},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {**FULL_VALID_SETTINGS_DICT, "usta": {}},
            "usta.api_key",
            id="missing_usta_api_key",
        ),
        pytest.param(
            {
                **FULL_VALID_SETTINGS_DICT,
                "usta": {**FULL_VALID_SETTINGS_DICT["usta"], "tlp_level": "purple"},
            },
            "usta.tlp_level",
            id="invalid_usta_tlp_level",
        ),
        pytest.param(
            {
                **FULL_VALID_SETTINGS_DICT,
                "usta": {**FULL_VALID_SETTINGS_DICT["usta"], "page_size": 5000},
            },
            "usta.page_size",
            id="invalid_usta_page_size",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`)
    MUST raise a `ConfigValidationError` on invalid input.
    """
    with pytest.raises(ConfigValidationError) as err:
        _fake_settings(settings_dict)()
    assert "Error validating configuration" in str(err)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = _fake_settings({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})()

    assert settings.connector.id == "8188b707-0b74-49e0-ba39-59b0c77f85da"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_apply_connector_defaults():
    """Without any connector variable, the USTA defaults MUST be applied."""
    settings = _fake_settings({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})()

    assert settings.connector.name == "USTA"
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period == timedelta(minutes=30)
    assert "indicator" in settings.connector.scope


def test_to_helper_config_is_pycti_compatible():
    """`to_helper_config()` MUST expose a `pycti.OpenCTIConnectorHelper` compatible dict."""
    settings = _fake_settings(FULL_VALID_SETTINGS_DICT)()
    helper_config = settings.to_helper_config()

    assert isinstance(helper_config, dict)
    # The OpenCTI token is revealed for pycti only
    assert helper_config["opencti"]["token"] == "test-token"
    # The scope is serialized as a comma-separated string for pycti
    assert helper_config["connector"]["scope"] == "indicator,report"
    assert helper_config["connector"]["type"] == "EXTERNAL_IMPORT"
    assert helper_config["connector"]["duration_period"] == "PT30M"
    # Connector secrets are NOT leaked into the helper config
    assert helper_config["usta"]["api_key"] != "test-api-key"
