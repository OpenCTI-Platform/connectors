import warnings
from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings

# Minimal set of variables required to build a valid `ConnectorSettings`:
# every other field declares a default in `settings.py`.
MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
    },
    "datadog": {
        "token": "test-api-key",
        "app_key": "test-app-key",
    },
}


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
                    "name": "DataDog",
                    "scope": "stix2",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "datadog": {
                    "token": "test-api-key",
                    "app_key": "test-app-key",
                    "api_base_url": "https://api.datadoghq.eu",
                    "app_base_url": "https://app.datadoghq.eu",
                    "import_start_date": "2024-01-01T00:00:00Z",
                    "max_tlp": "TLP:RED",
                    "batch_size": 500,
                    "import_alerts": False,
                    "create_incident_response_cases": True,
                    "alert_priorities": "P1,P2",
                    "alert_tags_filter": "env:prod, team:secops",
                    "extract_observables_from_alerts": False,
                    "include_alert_context": False,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            MINIMAL_VALID_SETTINGS_DICT,
            id="minimal_valid_settings_dict",
        ),
        pytest.param(
            {**MINIMAL_VALID_SETTINGS_DICT, "connector": {}},
            id="empty_connector_section_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.datadog, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {},
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {
                    "id": "connector-id",
                },
                "datadog": {
                    "token": "test-api-key",
                    "app_key": "test-app-key",
                },
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
                    "id": 12345,
                },
                "datadog": {
                    "token": "test-api-key",
                    "app_key": "test-app-key",
                },
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                },
                "datadog": {
                    "app_key": "test-app-key",
                },
            },
            id="missing_datadog_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                },
                "datadog": {
                    "token": "test-api-key",
                    "app_key": "test-app-key",
                    "batch_size": "not-a-number",
                },
            },
            id="invalid_datadog_batch_size",
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

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)


def test_settings_should_migrate_deprecated_import_interval():
    """
    Test that the deprecated `DATADOG_IMPORT_INTERVAL` (minutes) is automatically
    migrated to `CONNECTOR_DURATION_PERIOD` via `DeprecatedField` metadata in
    `BaseConnectorSettings`.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "datadog": {
                        "token": "test-api-key",
                        "app_key": "test-app-key",
                        "import_interval": 30,
                    },
                }
            )

    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always")
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == timedelta(minutes=30)
    warning_messages = [str(warning.message) for warning in caught_warnings]
    assert any("import_interval" in message for message in warning_messages)


def test_settings_should_prefer_duration_period_over_deprecated_import_interval():
    """
    When both `CONNECTOR_DURATION_PERIOD` and the deprecated `DATADOG_IMPORT_INTERVAL`
    are set, the new variable MUST win and the deprecated one MUST be ignored.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "connector": {
                        "id": "connector-id",
                        "duration_period": "PT15M",
                    },
                    "datadog": {
                        "token": "test-api-key",
                        "app_key": "test-app-key",
                        "import_interval": 30,
                    },
                }
            )

    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always")
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == timedelta(minutes=15)
    warning_messages = [str(warning.message) for warning in caught_warnings]
    assert any("import_interval" in message for message in warning_messages)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "ac3f08df-af45-4669-aec6-25b0e6487094"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_default_connector_section():
    """The `CONNECTOR_*` variables MUST fall back on this connector's own defaults."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.name == "DataDog"
    assert settings.connector.scope == ["stix2"]
    assert settings.connector.duration_period == timedelta(hours=1)


def test_settings_should_default_datadog_section():
    """Every optional `DATADOG_*` variable MUST fall back on its documented default."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.datadog.api_base_url == "https://api.datadoghq.com"
    assert settings.datadog.app_base_url == "https://app.datadoghq.com"
    assert settings.datadog.import_start_date is None
    assert settings.datadog.max_tlp == "TLP:AMBER"
    assert settings.datadog.batch_size == 100
    assert settings.datadog.import_alerts is True
    assert settings.datadog.create_incident_response_cases is False
    assert settings.datadog.alert_priorities == ["P1", "P2", "P3", "P4"]
    assert settings.datadog.alert_tags_filter == []
    assert settings.datadog.extract_observables_from_alerts is True
    assert settings.datadog.include_alert_context is True


def test_settings_should_hide_secrets():
    """The DataDog API key and Application key MUST be redacted when dumped."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.datadog.token.get_secret_value() == "test-api-key"
    assert settings.datadog.app_key.get_secret_value() == "test-app-key"
    assert "test-api-key" not in str(settings.datadog)
    assert "test-app-key" not in str(settings.datadog)


def test_settings_should_parse_comma_separated_lists():
    """`DATADOG_ALERT_PRIORITIES` / `DATADOG_ALERT_TAGS_FILTER` MUST accept env-style CSV values."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "datadog": {
                        "token": "test-api-key",
                        "app_key": "test-app-key",
                        "alert_priorities": "P1, P2 ,P3",
                        "alert_tags_filter": "env:prod,team:secops,",
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.datadog.alert_priorities == ["P1", "P2", "P3"]
    assert settings.datadog.alert_tags_filter == ["env:prod", "team:secops"]
