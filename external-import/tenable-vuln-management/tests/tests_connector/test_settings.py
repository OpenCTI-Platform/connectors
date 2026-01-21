from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from tenable_vuln_management import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "tio": {
                    "num_thread": 1,
                    "api_base_url": "https://cloud.tenable.com",
                    "api_access_key": "SecretStr",
                    "api_secret_key": "SecretStr",
                    "api_timeout": 30,
                    "api_backoff": 1,
                    "api_retries": 5,
                    "export_since": "1970-01-01T00:00:00+00",
                    "min_severity": "low",
                    "marking_definition": "TLP:CLEAR",
                    "num_threads": None,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "tio": {
                    "num_thread": 1,
                    "api_base_url": "https://cloud.tenable.com",
                    "api_access_key": "SecretStr",
                    "api_secret_key": "SecretStr",
                },
            },
            id="minimal_valid_settings_dict",
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
    assert isinstance(settings.tio, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "tio": {
                    "num_thread": 1,
                    "api_base_url": "https://cloud.tenable.com",
                    "api_access_key": "SecretStr",
                    "api_secret_key": "SecretStr",
                    "api_timeout": 30,
                    "api_backoff": 1,
                    "api_retries": 5,
                    "export_since": "1970-01-01T00:00:00+00",
                    "min_severity": "low",
                    "marking_definition": "TLP:CLEAR",
                    "num_threads": None,
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "tio": {
                    "num_thread": 1,
                    "api_base_url": "https://cloud.tenable.com",
                    "api_access_key": "SecretStr",
                    "api_secret_key": "SecretStr",
                    "api_timeout": 30,
                    "api_backoff": 1,
                    "api_retries": 5,
                    "export_since": "1970-01-01T00:00:00+00",
                    "min_severity": "low",
                    "marking_definition": "TLP:CLEAR",
                    "num_threads": None,
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

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

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
