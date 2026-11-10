from copy import deepcopy
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings

CONNECTOR_ID_DEFAULT = "4191560a-1678-4a2d-be88-d4dc22097031"

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "ocd": {
        "datalake_token": "test-datalake-token",
        "worldwatch_api_key": "test-worldwatch-api-key",
    },
}

FULL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Orange Cyberdefense Cyber Threat Intelligence",
        "scope": "Orange-Cyberdefense",
        "log_level": "error",
        "duration_period": "PT45M",
    },
    "ocd": {
        "import_datalake": True,
        "import_threat_library": True,
        "import_worldwatch": True,
        "datalake_env": "prod",
        "datalake_token": "test-datalake-token",
        "datalake_queries": (
            '[{"query_hash":"bb08a750538baea3e1c8cda0ae5b3aca",'
            '"label":"high_confidence_network_iocs"}]'
        ),
        "datalake_create_observables": True,
        "datalake_ignore_unscored_indicators": True,
        "datalake_ignore_whitelisted_indicators": True,
        "datalake_fallback_score": 0,
        "datalake_add_tags_as_labels": True,
        "datalake_add_scores_as_labels": True,
        "datalake_add_score": True,
        "datalake_add_tlp": True,
        "datalake_add_extref": True,
        "datalake_add_summary": True,
        "datalake_add_related": True,
        "datalake_add_sightings": True,
        "datalake_add_createdby": True,
        "datalake_zip_file_path": "/opt/opencti-connector-orange-cyberdefense/data",
        "datalake_zip_file_delete": True,
        "datalake_curate_labels": True,
        "datalake_threat_actor_as_intrusion_set": True,
        "worldwatch_api_key": "test-worldwatch-api-key",
        "worldwatch_import_indicators": True,
        "worldwatch_import_indicators_lookback": 2592000,
        "worldwatch_import_threat_entities": True,
        "worldwatch_start_date": "2026-01-01",
        "reset_state": False,
    },
}


def build_fake_settings(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    """Build a `ConnectorSettings` subclass reading the given dict instead of env/config vars."""

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(deepcopy(settings_dict))

    return FakeConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    settings = build_fake_settings(settings_dict)()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.ocd, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """Test that the minimal settings yield the documented defaults."""
    settings = build_fake_settings(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.name == "Orange Cyberdefense Cyber Threat Intelligence"
    assert settings.connector.scope == ["Orange-Cyberdefense"]
    assert settings.connector.log_level == "info"
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period == timedelta(minutes=30)

    ocd = settings.ocd
    assert ocd.import_datalake is True
    assert ocd.import_threat_library is True
    assert ocd.import_worldwatch is True
    assert ocd.datalake_env == "prod"
    assert ocd.datalake_token.get_secret_value() == "test-datalake-token"
    assert ocd.datalake_queries is None
    assert ocd.datalake_create_observables is True
    assert ocd.datalake_ignore_unscored_indicators is True
    assert ocd.datalake_ignore_whitelisted_indicators is True
    assert ocd.datalake_fallback_score == 0
    assert ocd.datalake_add_tags_as_labels is True
    assert ocd.datalake_add_scores_as_labels is True
    assert ocd.datalake_add_score is True
    assert ocd.datalake_add_tlp is True
    assert ocd.datalake_add_extref is True
    assert ocd.datalake_add_summary is True
    assert ocd.datalake_add_related is True
    assert ocd.datalake_add_sightings is True
    assert ocd.datalake_add_createdby is True
    assert (
        ocd.datalake_zip_file_path == "/opt/opencti-connector-orange-cyberdefense/data"
    )
    assert ocd.datalake_zip_file_delete is True
    assert ocd.datalake_curate_labels is True
    assert ocd.datalake_threat_actor_as_intrusion_set is True
    assert ocd.worldwatch_api_key.get_secret_value() == "test-worldwatch-api-key"
    assert ocd.worldwatch_import_indicators is True
    assert ocd.worldwatch_import_indicators_lookback == 2592000
    assert ocd.worldwatch_import_threat_entities is True
    assert ocd.worldwatch_start_date == "2026-01-01"
    assert ocd.reset_state is False


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""
    settings = build_fake_settings(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.id == CONNECTOR_ID_DEFAULT
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "ocd": MINIMAL_VALID_SETTINGS_DICT["ocd"],
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "ocd": {"worldwatch_api_key": "test-worldwatch-api-key"},
            },
            id="missing_datalake_token",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "ocd": {"datalake_token": "test-datalake-token"},
            },
            id="missing_worldwatch_api_key",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"id": 123456},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"duration_period": "PT30S"},
            },
            id="duration_period_below_one_minute",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "ocd": {
                    **MINIMAL_VALID_SETTINGS_DICT["ocd"],
                    "datalake_fallback_score": "not-a-number",
                },
            },
            id="invalid_datalake_fallback_score",
        ),
        pytest.param(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "ocd": {
                    **MINIMAL_VALID_SETTINGS_DICT["ocd"],
                    "import_datalake": "not-a-boolean",
                },
            },
            id="invalid_import_datalake",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    with pytest.raises(ConfigValidationError) as err:
        build_fake_settings(settings_dict)()
    assert str("Error validating configuration") in str(err)


def test_settings_should_migrate_deprecated_interval():
    """The deprecated `OCD_INTERVAL` (minutes) MUST migrate to `CONNECTOR_DURATION_PERIOD`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {},
        "ocd": {**MINIMAL_VALID_SETTINGS_DICT["ocd"], "interval": 60},
    }

    with pytest.warns(UserWarning, match="ocd.interval"):
        settings = build_fake_settings(settings_dict)()

    assert settings.connector.duration_period == timedelta(minutes=60)


def test_settings_should_prefer_duration_period_over_deprecated_interval():
    """When both are set, `CONNECTOR_DURATION_PERIOD` MUST win over `OCD_INTERVAL`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "connector": {"duration_period": "PT2H"},
        "ocd": {**MINIMAL_VALID_SETTINGS_DICT["ocd"], "interval": 60},
    }

    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = build_fake_settings(settings_dict)()

    assert settings.connector.duration_period == timedelta(hours=2)


@pytest.mark.parametrize(
    "deprecated_name, new_name, raw_value, expected_value",
    [
        ("create_observables", "datalake_create_observables", "false", False),
        (
            "ignore_unscored_indicators",
            "datalake_ignore_unscored_indicators",
            "false",
            False,
        ),
        (
            "ignore_whitelisted_indicators",
            "datalake_ignore_whitelisted_indicators",
            "false",
            False,
        ),
        ("fallback_score", "datalake_fallback_score", "42", 42),
        ("curate_labels", "datalake_curate_labels", "false", False),
        (
            "threat_actor_as_intrusion_set",
            "datalake_threat_actor_as_intrusion_set",
            "false",
            False,
        ),
        (
            "import_worldwatch_start_date",
            "worldwatch_start_date",
            "2025-03-01",
            "2025-03-01",
        ),
    ],
)
def test_settings_should_migrate_deprecated_variables(
    deprecated_name, new_name, raw_value, expected_value
):
    """Each deprecated `OCD_*` alias MUST migrate to its new variable."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "ocd": {**MINIMAL_VALID_SETTINGS_DICT["ocd"], deprecated_name: raw_value},
    }

    with pytest.warns(UserWarning, match=f"ocd.{deprecated_name}"):
        settings = build_fake_settings(settings_dict)()

    assert getattr(settings.ocd, new_name) == expected_value


def test_settings_should_migrate_deprecated_worldwatch_api_key():
    """The deprecated `OCD_IMPORT_WORLDWATCH_API_KEY` MUST migrate to `OCD_WORLDWATCH_API_KEY`."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "ocd": {
            "datalake_token": "test-datalake-token",
            "import_worldwatch_api_key": "legacy-api-key",
        },
    }

    with pytest.warns(UserWarning, match="ocd.import_worldwatch_api_key"):
        settings = build_fake_settings(settings_dict)()

    assert settings.ocd.worldwatch_api_key.get_secret_value() == "legacy-api-key"


def test_settings_should_prefer_new_variable_over_deprecated_alias():
    """When both are set, the new variable MUST win over its deprecated alias."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "ocd": {
            **MINIMAL_VALID_SETTINGS_DICT["ocd"],
            "fallback_score": 9,
            "datalake_fallback_score": 5,
        },
    }

    with pytest.warns(UserWarning, match="Using only 'ocd.datalake_fallback_score'"):
        settings = build_fake_settings(settings_dict)()

    assert settings.ocd.datalake_fallback_score == 5
