from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
from internal_enrichment_connector.settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "onyphe": {
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
        "scope": "ipv4-addr,hostname",
        "log_level": "info",
        "auto": True,
        "max_tlp": "TLP:GREEN",
    },
    "onyphe": {
        "api_key": "test-api-key",
        "base_url": "http://onyphe.test/api/v2/",
        "category": "riskscan",
        "time_since": "2w",
        "default_score": 70,
        "import_search_results": False,
        "create_note": True,
        "import_full_data": True,
        "pivot_threshold": 25,
        "indicator_max_results": 500,
        "pattern_type": "onyphe-oql",
        "enrichment_types": "IPv4-Address, Vulnerability",
        "text_fingerprints": "favicon-sha256,ssh-fingerprint-sha256",
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Build `ConnectorSettings` from a dict instead of env vars or `config.yml`."""

    class FakeConnectorSettings(ConnectorSettings):
        """`ConnectorSettings` reading its config from `settings_dict`."""

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """`ConnectorSettings` accepts a valid config dict."""
    settings = build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.onyphe, BaseConfigModel) is True


def test_settings_should_parse_full_input():
    """Every value of a full config dict reaches the settings, with its type."""
    settings = build_settings(FULL_VALID_SETTINGS_DICT)

    assert settings.connector.scope == ["ipv4-addr", "hostname"]
    assert settings.connector.max_tlp == TLPLevel.GREEN
    assert settings.onyphe.api_key.get_secret_value() == "test-api-key"
    assert settings.onyphe.base_url == "http://onyphe.test/api/v2/"
    assert settings.onyphe.category == "riskscan"
    assert settings.onyphe.time_since == "2w"
    assert settings.onyphe.default_score == 70
    assert settings.onyphe.import_search_results is False
    assert settings.onyphe.create_note is True
    assert settings.onyphe.import_full_data is True
    assert settings.onyphe.pivot_threshold == 25
    assert settings.onyphe.indicator_max_results == 500
    assert settings.onyphe.pattern_type == "onyphe-oql"
    assert settings.onyphe.enrichment_types == ["IPv4-Address", "Vulnerability"]
    assert settings.onyphe.text_fingerprints == [
        "favicon-sha256",
        "ssh-fingerprint-sha256",
    ]


def test_settings_should_apply_defaults():
    """The minimal config dict yields the documented defaults."""
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "ONYPHE"
    assert settings.connector.scope == [
        "ipv4-addr",
        "ipv6-addr",
        "indicator",
        "hostname",
        "x509-certificate",
        "text",
    ]
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.auto is False
    assert settings.connector.log_level == "error"
    assert settings.connector.max_tlp == TLPLevel.AMBER
    assert settings.onyphe.base_url == "https://www.onyphe.io/api/v2/"
    assert settings.onyphe.category == "ctiscan"
    assert settings.onyphe.time_since == "1w"
    assert settings.onyphe.default_score == 50
    assert settings.onyphe.import_search_results is True
    assert settings.onyphe.create_note is False
    assert settings.onyphe.import_full_data is False
    assert settings.onyphe.pivot_threshold == 10
    assert settings.onyphe.indicator_max_results == 1000
    assert settings.onyphe.pattern_type == "onyphe"
    assert settings.onyphe.enrichment_types == []
    assert settings.onyphe.text_fingerprints == []


def test_settings_should_default_connector_id():
    """Without `connector.id`, the settings use the UUIDv4 default of the connector."""
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == "5d5d8a0c-029d-40ed-a711-371b664c43e6"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_accept_empty_list_values():
    """Empty comma-separated values (the legacy default) give empty lists."""
    settings = build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "onyphe": {
                "api_key": "test-api-key",
                "enrichment_types": "",
                "text_fingerprints": "",
            },
        }
    )

    assert settings.onyphe.enrichment_types == []
    assert settings.onyphe.text_fingerprints == []


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "onyphe": {"api_key": "test-api-key"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "onyphe": {"api_key": "test-api-key"},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "onyphe": {},
            },
            id="missing_onyphe_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """`ConnectorSettings` raises `ConfigValidationError` on an invalid config dict."""
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)
    assert "Error validating configuration" in str(err)


def test_settings_should_migrate_deprecated_onyphe_max_tlp():
    """The deprecated `onyphe.max_tlp` (`ONYPHE_MAX_TLP`) migrates to `connector.max_tlp`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "onyphe": {"api_key": "test-api-key", "max_tlp": "TLP:RED"},
    }

    with pytest.warns(UserWarning, match="onyphe.max_tlp"):
        settings = build_settings(settings_dict)

    assert settings.connector.max_tlp == TLPLevel.RED


def test_settings_should_prefer_connector_max_tlp_over_deprecated_one():
    """When both are set, `connector.max_tlp` wins over `onyphe.max_tlp`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"max_tlp": "TLP:GREEN"},
        "onyphe": {"api_key": "test-api-key", "max_tlp": "TLP:RED"},
    }

    with pytest.warns(UserWarning, match="Using only 'connector.max_tlp'"):
        settings = build_settings(settings_dict)

    assert settings.connector.max_tlp == TLPLevel.GREEN
