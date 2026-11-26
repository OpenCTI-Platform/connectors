from copy import deepcopy
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "vulmatch": {
        "api_key": "test-api-key",
    },
}


def build_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    """Instantiate `ConnectorSettings` from a dict instead of env/config vars."""

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return the given config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(deepcopy(settings_dict))

    return FakeConnectorSettings()


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT12H",
                },
                "vulmatch": {
                    "base_url": "https://api.vulmatch.com/",
                    "api_key": "test-api-key",
                    "sbom_only": True,
                    "cvss_v2_score_min": 5,
                    "cvss_v3_score_min": 7,
                    "cvss_v4_score_min": 8,
                    "epss_score_min": 0.5,
                    "days_to_backfill": 30,
                },
            },
            id="full_valid_settings_dict",
        ),
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
    settings = build_settings(settings_dict)

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.vulmatch, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """
    Test that `ConnectorSettings` applies the defaults needed to deploy the connector
    from the catalog with only the OpenCTI URL and token and the Vulmatch API key.
    """
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.name == "Vulmatch"
    assert settings.connector.scope == ["vulmatch"]
    assert settings.connector.log_level == "error"
    assert settings.connector.duration_period == timedelta(days=1)
    assert str(settings.vulmatch.base_url) == "https://api.vulmatch.com/"
    assert settings.vulmatch.api_key.get_secret_value() == "test-api-key"
    assert settings.vulmatch.sbom_only is False
    assert settings.vulmatch.cvss_v2_score_min == -1
    assert settings.vulmatch.cvss_v3_score_min == -1
    assert settings.vulmatch.cvss_v4_score_min == -1
    assert settings.vulmatch.epss_score_min == -1
    assert settings.vulmatch.days_to_backfill == 90


def test_settings_should_default_connector_id():
    """
    Test that `ConnectorSettings` provides a default UUIDv4 `connector.id`,
    so the connector can be deployed from the catalog without manual input.
    """
    settings = build_settings(MINIMAL_VALID_SETTINGS_DICT)

    assert settings.connector.id == "bb033198-4bc8-4349-aed9-9c090a8a4a9b"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_keep_cvss_score_filters_as_integers():
    """
    Test that the CVSS score filters are parsed as integers, as before the
    migration, so the values sent to the Vulmatch API keep the same format
    (`7`, not `7.0`).
    """
    settings = build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "vulmatch": {
                "api_key": "test-api-key",
                "cvss_v2_score_min": "5",
                "cvss_v3_score_min": "7",
                "cvss_v4_score_min": "9",
            },
        }
    )

    for score in (
        settings.vulmatch.cvss_v2_score_min,
        settings.vulmatch.cvss_v3_score_min,
        settings.vulmatch.cvss_v4_score_min,
    ):
        assert type(score) is int
    assert settings.vulmatch.cvss_v2_score_min == 5
    assert settings.vulmatch.cvss_v3_score_min == 7
    assert settings.vulmatch.cvss_v4_score_min == 9


@pytest.mark.parametrize(
    "field_name",
    ["cvss_v2_score_min", "cvss_v3_score_min", "cvss_v4_score_min"],
)
def test_settings_should_reject_decimal_cvss_score_filters(field_name):
    """Test that the CVSS score filters reject decimal values."""
    with pytest.raises(ConfigValidationError) as err:
        build_settings(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "vulmatch": {"api_key": "test-api-key", field_name: "7.5"},
            }
        )

    assert f"vulmatch.{field_name}" in str(err.value.__cause__)


def test_settings_should_accept_decimal_epss_score_filter():
    """
    Test that the EPSS score filter accepts decimal values
    (EPSS scores range from 0 to 1).
    """
    settings = build_settings(
        {
            **MINIMAL_VALID_SETTINGS_DICT,
            "vulmatch": {
                "api_key": "test-api-key",
                "epss_score_min": "0.05",
            },
        }
    )

    assert settings.vulmatch.epss_score_min == 0.05


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "url", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {},
                "vulmatch": {
                    "api_key": "test-api-key",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": 123456,
                },
                "vulmatch": {
                    "api_key": "test-api-key",
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "vulmatch": {},
            },
            "vulmatch.api_key",
            id="missing_vulmatch_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The dotted path of the field expected to fail validation
    """
    with pytest.raises(ConfigValidationError) as err:
        build_settings(settings_dict)

    assert "Error validating configuration" in str(err.value)
    assert field_name in str(err.value.__cause__)


def test_settings_should_migrate_deprecated_interval_days():
    """
    Test that the deprecated `vulmatch.interval_days` (in days) is migrated
    to `connector.duration_period` when it is set alone.
    """
    with pytest.warns(UserWarning, match="vulmatch.interval_days"):
        settings = build_settings(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "vulmatch": {
                    "api_key": "test-api-key",
                    "interval_days": "2",
                },
            }
        )

    assert settings.connector.duration_period == timedelta(days=2)


def test_settings_should_prefer_duration_period_over_interval_days():
    """
    Test that `connector.duration_period` wins over the deprecated
    `vulmatch.interval_days` when both are set.
    """
    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = build_settings(
            {
                **MINIMAL_VALID_SETTINGS_DICT,
                "connector": {"duration_period": "PT6H"},
                "vulmatch": {
                    "api_key": "test-api-key",
                    "interval_days": "2",
                },
            }
        )

    assert settings.connector.duration_period == timedelta(hours=6)


@pytest.mark.parametrize(
    "base_url",
    ["api.example.com", "ftp://api.example.com", "not a url"],
)
def test_settings_should_reject_invalid_base_url(base_url):
    """`vulmatch.base_url` must be an absolute HTTP(S) URL."""
    settings_dict = {
        **MINIMAL_VALID_SETTINGS_DICT,
        "vulmatch": {**MINIMAL_VALID_SETTINGS_DICT["vulmatch"], "base_url": base_url},
    }

    with pytest.raises(ConfigValidationError):
        build_settings(settings_dict)
