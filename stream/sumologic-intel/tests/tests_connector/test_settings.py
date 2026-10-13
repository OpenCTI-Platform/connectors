from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from sumologic_intel_connector import ConnectorSettings

BASE_VALID_SETTINGS = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "sumologic",
        "log_level": "error",
        "live_stream_id": "test-live-stream-id",
        "live_stream_listen_delete": True,
        "live_stream_no_dependencies": True,
    },
    "sumologic_intel": {
        "api_base_url": "https://api.sumologic.com",
        "access_id": "test-access-id",
        "access_key": "test-access-key",
    },
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            BASE_VALID_SETTINGS,
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "live_stream_id": "test-live-stream-id",
                },
                "sumologic_intel": {
                    "api_base_url": "https://api.sumologic.com",
                    "access_id": "test-access-id",
                    "access_key": "test-access-key",
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
    assert isinstance(settings.sumologic_intel, BaseConfigModel) is True


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
                **BASE_VALID_SETTINGS,
                "opencti": {
                    "url": "http://localhost:8080",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **BASE_VALID_SETTINGS,
                "connector": {
                    "id": 12345,
                    "name": "Test Connector",
                    "scope": "sumologic",
                    "live_stream_id": "test-live-stream-id",
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **BASE_VALID_SETTINGS,
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "sumologic",
                },
            },
            "connector.live_stream_id",
            id="missing_connector_live_stream_id",
        ),
        pytest.param(
            {
                **BASE_VALID_SETTINGS,
                "sumologic_intel": {
                    "access_id": "test-access-id",
                    "access_key": "test-access-key",
                },
            },
            "sumologic_intel.api_base_url",
            id="missing_api_base_url",
        ),
        pytest.param(
            {
                **BASE_VALID_SETTINGS,
                "sumologic_intel": {
                    "api_base_url": "https://api.sumologic.com",
                    "access_id": "test-access-id",
                },
            },
            "sumologic_intel.access_key",
            id="missing_access_key",
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
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
