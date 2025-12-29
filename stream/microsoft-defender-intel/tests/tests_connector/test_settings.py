from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from microsoft_defender_intel_connector import ConnectorSettings


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
                    "live_stream_id": "fake_id--66bd9a11-02e1-47c1-995a-f152caa5866",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                },
                "microsoft_defender_intel": {
                    "tenant_id": "test-tenant-id",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "login_url": "https://login.microsoft.com",
                    "base_url": "https://api.securitycenter.microsoft.com",
                    "resource_path": "api/indicators",
                    "expire_time": 30,
                    "action": "Alert",
                    "passive_only": False,
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
                "connector": {
                    "live_stream_id": "fake_id--66bd9a11-02e1-47c1-995a-f152caa5866",
                },
                "microsoft_defender_intel": {
                    "tenant_id": "test-tenant-id",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
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
    assert isinstance(settings.microsoft_defender_intel, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "live_stream_id": "fake_id--66bd9a11-02e1-47c1-995a-f152caa5866",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                },
                "microsoft_defender_intel": {
                    "tenant_id": "test-tenant-id",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "login_url": "https://login.microsoft.com",
                    "base_url": "https://api.securitycenter.microsoft.com",
                    "resource_path": "api/indicators",
                    "expire_time": 30,
                    "action": "Alert",
                    "passive_only": False,
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
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
                    "live_stream_id": "fake_id--66bd9a11-02e1-47c1-995a-f152caa5866",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                },
                "microsoft_defender_intel": {
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            "microsoft_defender_intel.tenant_id",
            id="missing_microsoft_defender_intel_tenant_id",
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
