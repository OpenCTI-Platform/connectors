from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import (
    BaseConfigModel,
    BaseInternalEnrichmentConnectorSettings,
    ConfigValidationError,
)
from settings import ConnectorSettings

CONNECTOR_ID_DEFAULT = "39e3373c-b4e8-4706-87d6-ab867a90e740"

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "rst_ioc_lookup": {
        "api_key": "test-api-key",
    },
}

FULL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "IPv4-Addr,Domain-Name",
        "log_level": "error",
        "auto": True,
        "max_tlp": "TLP:GREEN",
    },
    "rst_ioc_lookup": {
        "base_url": "https://api.example.com/v1",
        "api_key": "test-api-key",
        "update_confidence": False,
        "update_score": False,
        "update_valid_from": False,
        "score_type": "last",
        "update_description_action": "append",
        "detection_flag_threshold": 60,
        "label_format": "long",
        "timeout": 30,
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env vars or `config.yml`."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def test_settings_should_be_internal_enrichment_connector_settings():
    assert issubclass(ConnectorSettings, BaseInternalEnrichmentConnectorSettings)


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    settings = build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.rst_ioc_lookup, BaseConfigModel)
    assert settings.rst_ioc_lookup.api_key.get_secret_value() == "test-api-key"


def test_settings_should_apply_full_input():
    settings = build_settings(FULL_VALID_SETTINGS_DICT)

    assert settings.connector.id == "connector-id"
    assert settings.connector.name == "Test Connector"
    assert settings.connector.scope == ["IPv4-Addr", "Domain-Name"]
    assert settings.connector.auto is True
    assert settings.connector.max_tlp == "green"
    assert settings.rst_ioc_lookup.base_url == "https://api.example.com/v1"
    assert settings.rst_ioc_lookup.update_confidence is False
    assert settings.rst_ioc_lookup.update_score is False
    assert settings.rst_ioc_lookup.update_valid_from is False
    assert settings.rst_ioc_lookup.score_type == "last"
    assert settings.rst_ioc_lookup.update_description_action == "append"
    assert settings.rst_ioc_lookup.detection_flag_threshold == 60
    assert settings.rst_ioc_lookup.label_format == "long"
    assert settings.rst_ioc_lookup.timeout == 30


def test_settings_should_apply_defaults():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "RST IoC Lookup"
    assert settings.connector.scope == [
        "IPv4-Addr",
        "Domain-Name",
        "Url",
        "StixFile",
        "indicator",
    ]
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.auto is False
    assert settings.connector.log_level == "error"
    assert settings.connector.max_tlp == "amber+strict"
    assert settings.rst_ioc_lookup.base_url == "https://api.rstcloud.net/v1"
    assert settings.rst_ioc_lookup.update_confidence is True
    assert settings.rst_ioc_lookup.update_score is True
    assert settings.rst_ioc_lookup.update_valid_from is True
    assert settings.rst_ioc_lookup.score_type == "total"
    assert settings.rst_ioc_lookup.update_description_action == "overwrite"
    assert settings.rst_ioc_lookup.detection_flag_threshold == 45
    assert settings.rst_ioc_lookup.label_format == "short"
    assert settings.rst_ioc_lookup.timeout == 10


def test_settings_should_default_connector_id():
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == CONNECTOR_ID_DEFAULT
    assert UUID(settings.connector.id).version == 4


def test_settings_should_accept_legacy_section_name():
    settings_dict = {
        "opencti": MINIMAL_VALID_SETTINGS_DICT["opencti"],
        "connector": {},
        "rst-ioc-lookup": {"api_key": "legacy-api-key", "timeout": 5},
    }

    settings = build_settings(settings_dict)

    assert settings.rst_ioc_lookup.api_key.get_secret_value() == "legacy-api-key"
    assert settings.rst_ioc_lookup.timeout == 5


def test_settings_should_migrate_legacy_max_tlp():
    settings_dict = {
        "opencti": MINIMAL_VALID_SETTINGS_DICT["opencti"],
        "connector": {},
        "rst_ioc_lookup": {"api_key": "test-api-key", "max_tlp": "TLP:GREEN"},
    }

    with pytest.warns(UserWarning, match="rst_ioc_lookup.max_tlp"):
        settings = build_settings(settings_dict)

    assert settings.connector.max_tlp == "green"


def test_settings_should_prefer_connector_max_tlp_over_legacy_one():
    settings_dict = {
        "opencti": MINIMAL_VALID_SETTINGS_DICT["opencti"],
        "connector": {"max_tlp": "TLP:RED"},
        "rst_ioc_lookup": {"api_key": "test-api-key", "max_tlp": "TLP:GREEN"},
    }

    with pytest.warns(UserWarning, match="Using only 'connector.max_tlp'"):
        settings = build_settings(settings_dict)

    assert settings.connector.max_tlp == "red"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "rst_ioc_lookup": {"api_key": "test-api-key"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": MINIMAL_VALID_SETTINGS_DICT["opencti"],
                "connector": {"id": 123},
                "rst_ioc_lookup": {"api_key": "test-api-key"},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": MINIMAL_VALID_SETTINGS_DICT["opencti"],
                "connector": {},
                "rst_ioc_lookup": {},
            },
            id="missing_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)

    assert "Error validating configuration" in str(err)
