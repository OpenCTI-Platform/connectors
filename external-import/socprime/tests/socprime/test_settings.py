"""Unit tests for the SOC Prime Pydantic `ConnectorSettings`.

These tests validate the settings model in isolation, independently of environment
variables, by overriding `_load_config_dict` (the connectors-sdk wrap validator that
loads the raw config) with a fixed dict. They complement ``test_config.py`` (which
covers the OpenCTIConnectorHelper wiring and the env-based full ``model_dump``) by
adding explicit valid/invalid input coverage and the deprecated-interval migration.
"""

import warnings
from datetime import timedelta
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from socprime.settings import ConnectorSettings


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
                    "name": "Soc Prime",
                    "scope": "socprime",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "socprime": {
                    "api_key": "api-key",
                    "content_list_name": "name1,name2",
                    "job_ids": "job1,job2",
                    "siem_type": "devo,snowflake",
                    "indicator_siem_type": "sigma",
                    "tlp_level": "amber+strict",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                # Only `id` is required; name/scope/duration_period have defaults.
                "connector": {"id": "connector-id"},
                # `api_key` is required and at least one of content_list_name/job_ids.
                "socprime": {"api_key": "api-key", "job_ids": "job1"},
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict: dict[str, Any]) -> None:
    """`ConnectorSettings` should accept valid full and minimal configurations."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.socprime, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Soc Prime",
                    "scope": "socprime",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "socprime": {"api_key": "api-key", "job_ids": "job1"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": 123456,  # must be a string
                    "name": "Soc Prime",
                    "scope": "socprime",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "socprime": {"api_key": "api-key", "job_ids": "job1"},
            },
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(
    settings_dict: dict[str, Any],
) -> None:
    """`ConnectorSettings` should raise `ConfigValidationError` on invalid input."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err.value)


def test_settings_should_migrate_deprecated_interval() -> None:
    """The deprecated `SOCPRIME_INTERVAL_SEC` should migrate to `CONNECTOR_DURATION_PERIOD`.

    The connector historically scheduled runs with `socprime.interval_sec` (in seconds).
    That field is deprecated: providing it (without `connector.duration_period`) must
    populate `connector.duration_period` with the equivalent timedelta and emit a
    deprecation warning.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {"id": "connector-id"},
                    "socprime": {
                        "api_key": "api-key",
                        "job_ids": "job1",
                        "interval_sec": 5,  # deprecated field, in seconds
                    },
                }
            )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        settings = FakeConnectorSettings()

    # `interval_sec` (seconds) is migrated to `duration_period` and then nulled.
    assert settings.connector.duration_period == timedelta(seconds=5)
    assert settings.socprime.interval_sec is None

    warning_messages = [str(warning.message) for warning in caught]
    assert any("interval" in message.lower() for message in warning_messages)
