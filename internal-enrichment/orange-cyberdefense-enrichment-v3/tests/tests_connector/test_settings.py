from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
from settings import ConnectorSettings

CONNECTOR_ID_DEFAULT = "cb4ab06c-1514-4e80-8b35-46cbf914781b"

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "ocd_enrich": {
        "datalake_token": "test-datalake-token",
    },
}

FULL_VALID_SETTINGS_DICT: dict[str, Any] = {
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
        "max_tlp": "amber",
    },
    "ocd_enrich": {
        "datalake_token": "test-datalake-token",
        "datalake_env": "preprod",
        "ignore_unscored_indicators": False,
        "ignore_whitelisted_indicators": False,
        "fallback_score": 42,
        "add_tags_as_labels": False,
        "add_scores_as_labels": False,
        "add_score": False,
        "add_tlp": False,
        "add_extref": False,
        "add_summary": False,
        "add_related": False,
        "add_sightings": False,
        "add_createdby": False,
        "curate_labels": False,
        "threat_actor_as_intrusion_set": False,
    },
}


def _build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        """Subclass of `ConnectorSettings` reading its config from `settings_dict` only."""

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
    """The settings MUST accept a valid config dict and expose every section."""
    settings = _build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel)
    assert isinstance(settings.connector, BaseConfigModel)
    assert isinstance(settings.ocd_enrich, BaseConfigModel)


def test_settings_should_apply_defaults():
    """The minimal config dict MUST yield the documented defaults."""
    settings = _build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Orange Cyberdefense CTI Enrichment"
    assert settings.connector.scope == [
        "IPv4-Addr",
        "IPv6-Addr",
        "Domain-Name",
        "URL",
        "Email-Addr",
        "Autonomous-System",
        "X509-Certificate",
        "Cryptocurrency-Wallet",
        "StixFile",
        "Phone-Number",
    ]
    assert settings.connector.log_level == "info"
    assert settings.connector.auto is False
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.max_tlp == TLPLevel.GREEN

    ocd_enrich = settings.ocd_enrich
    assert ocd_enrich.datalake_token.get_secret_value() == "test-datalake-token"
    assert ocd_enrich.datalake_env == "prod"
    assert ocd_enrich.ignore_unscored_indicators is True
    assert ocd_enrich.ignore_whitelisted_indicators is True
    assert ocd_enrich.fallback_score == 0
    assert ocd_enrich.add_tags_as_labels is True
    assert ocd_enrich.add_scores_as_labels is True
    assert ocd_enrich.add_score is True
    assert ocd_enrich.add_tlp is True
    assert ocd_enrich.add_extref is True
    assert ocd_enrich.add_summary is True
    assert ocd_enrich.add_related is True
    assert ocd_enrich.add_sightings is True
    assert ocd_enrich.add_createdby is True
    assert ocd_enrich.curate_labels is True
    assert ocd_enrich.threat_actor_as_intrusion_set is True


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = _build_settings({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    assert settings.connector.id == CONNECTOR_ID_DEFAULT
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "opencti": {"url": "http://localhost:8080"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "connector": {"id": 123456}},
            id="invalid_connector_id",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "ocd_enrich": {}},
            id="missing_ocd_enrich_datalake_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "ocd_enrich": {
                    "datalake_token": "test-datalake-token",
                    "fallback_score": "not-a-number",
                },
            },
            id="invalid_ocd_enrich_fallback_score",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """The settings MUST raise a `ConfigValidationError` on an invalid config dict."""
    with pytest.raises(ConfigValidationError) as err:
        _build_settings(settings_dict)

    assert "Error validating configuration" in str(err)


def test_settings_should_migrate_deprecated_ocd_enrich_max_tlp_to_connector_max_tlp():
    """The deprecated `OCD_ENRICH_MAX_TLP` MUST be migrated to `CONNECTOR_MAX_TLP`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "ocd_enrich": {"datalake_token": "test-datalake-token", "max_tlp": "TLP:RED"},
    }

    with pytest.warns(UserWarning, match="ocd_enrich.max_tlp"):
        settings = _build_settings(settings_dict)

    assert settings.connector.max_tlp == TLPLevel.RED


def test_settings_should_prefer_connector_max_tlp_over_deprecated_one():
    """`CONNECTOR_MAX_TLP` MUST win when the deprecated `OCD_ENRICH_MAX_TLP` is also set."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"max_tlp": "amber"},
        "ocd_enrich": {"datalake_token": "test-datalake-token", "max_tlp": "TLP:RED"},
    }

    with pytest.warns(UserWarning, match="ocd_enrich.max_tlp"):
        settings = _build_settings(settings_dict)

    assert settings.connector.max_tlp == TLPLevel.AMBER
