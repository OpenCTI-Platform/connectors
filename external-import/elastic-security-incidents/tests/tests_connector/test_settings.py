from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


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
                    "id": "d790f4c0-84c1-4e91-8e6b-3a6f3a0e1234",
                    "name": "Elastic Security Incidents",
                    "scope": "elastic-security-incidents",
                    "log_level": "error",
                    "duration_period": "PT30M",
                },
                "elastic_security": {
                    "url": "https://elastic.example.com:9200",
                    "api_key": "test-api-key",
                    "kibana_url": "https://kibana.example.com",
                    "ca_cert": "/path/to/ca.crt",
                    "verify_ssl": True,
                    "import_start_date": "2024-01-01T00:00:00Z",
                    "import_alerts": True,
                    "import_cases": True,
                    "alert_statuses": "open,acknowledged",
                    "alert_rule_tags": "Domain: Endpoint,OS: Windows",
                    "case_statuses": "open,in-progress",
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
                "connector": {},
                "elastic_security": {
                    "url": "https://elastic.example.com:9200",
                    "api_key": "test-api-key",
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
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.elastic_security, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "settings",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {
                    "id": "d790f4c0-84c1-4e91-8e6b-3a6f3a0e1234",
                    "name": "Elastic Security Incidents",
                    "scope": "elastic-security-incidents",
                    "log_level": "error",
                    "duration_period": "PT30M",
                },
                "elastic_security": {
                    "url": "https://elastic.example.com:9200",
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
                    "name": "Elastic Security Incidents",
                    "scope": "elastic-security-incidents",
                    "log_level": "error",
                    "duration_period": "PT30M",
                },
                "elastic_security": {
                    "url": "https://elastic.example.com:9200",
                    "api_key": "test-api-key",
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
    :param field_name: The name of the invalid field (for documentation purposes)
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
