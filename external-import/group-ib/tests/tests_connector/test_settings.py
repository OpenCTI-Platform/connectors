from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Group-IB Test Connector",
                    "scope": "stix2,ipv4-addr,ipv6-addr",
                    "log_level": "error",
                    "duration_period": "PT4H",
                    "update_existing_data": True,
                },
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
                    "url": "https://tap.group-ib.com/api/v2/",
                    "proxy_ip": "10.0.0.5",
                    "proxy_port": "8080",
                    "extra_settings_schedule_time": "00:00",
                    "extra_settings_enable_statement_marking": False,
                    "collections_apt_threat_enable": True,
                    "collections_apt_threat_ttl": 90,
                    "collections_apt_threat_use_hunting_rules": True,
                    "collections_hi_threat_enable": False,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`)
    accepts valid input. For the test purpose, `BaseConnectorSettings._load_config_dict` is
    overridden to return a fake but valid dict (instead of the env/config vars parsed from
    `config.yml`, `.env` or env vars).

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
    assert isinstance(settings.ti_api, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Group-IB Test Connector",
                    "scope": "stix2,ipv4-addr",
                    "log_level": "error",
                    "duration_period": "PT4H",
                },
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
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
                    "name": "Group-IB Test Connector",
                    "scope": "stix2,ipv4-addr",
                    "log_level": "error",
                    "duration_period": "PT4H",
                },
                "ti_api": {
                    "username": "user@example.com",
                    "token": "test-ti-token",
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`)
    raises on invalid input. For the test purpose, `BaseConnectorSettings._load_config_dict` is
    overridden to return a fake and invalid dict (instead of the env/config vars parsed from
    `config.yml`, `.env` or env vars).

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
    assert "Error validating configuration" in str(err.value)
