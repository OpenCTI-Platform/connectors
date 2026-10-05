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
                    "id": "connector-id",
                    "name": "Palo Alto Cortex XDR Intel",
                    "scope": "pan-cortex-xdr-intel",
                    "log_level": "error",
                    "live_stream_id": "test-stream-id",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                },
                "pan_cortex_xdr_intel": {
                    "api_base_url": "https://api-test.com",
                    "api_key_id": "test-key-id",
                    "api_key": "test-api-key",
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
                    "live_stream_id": "test-stream-id",
                },
                "pan_cortex_xdr_intel": {
                    "api_base_url": "https://api-test.com",
                    "api_key_id": "test-key-id",
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

    # Given: Valid input
    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    # When: We create a ConnectorSettings instance with valid input data
    settings = FakeConnectorSettings()

    # Then: The ConnectorSettings instance should be created successfully
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.pan_cortex_xdr_intel, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param(
            {},
            "url",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Palo Alto Cortex XDR Intel",
                    "scope": "pan-cortex-xdr-intel",
                    "live_stream_id": "test-stream-id",
                },
                "pan_cortex_xdr_intel": {
                    "api_base_url": "https://api-test.com",
                    "api_key_id": "test-key-id",
                    "api_key": "test-api-key",
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
                    "name": "Palo Alto Cortex XDR Intel",
                    "scope": "pan-cortex-xdr-intel",
                    "live_stream_id": "test-stream-id",
                },
                "pan_cortex_xdr_intel": {
                    "api_base_url": "https://api-test.com",
                    "api_key": "test-api-key",
                },
            },
            "pan_cortex_xdr_intel.api_key_id",
            id="missing_api_key_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Palo Alto Cortex XDR Intel",
                    "scope": "pan-cortex-xdr-intel",
                    "live_stream_id": "test-stream-id",
                },
                "pan_cortex_xdr_intel": {
                    "api_key_id": "test-key-id",
                    "api_key": "test-api-key",
                },
            },
            "pan_cortex_xdr_intel.api_base_url",
            id="missing_pan_cortex_xdr_intel_api_base_url",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The pydantic field path expected to be reported as invalid/missing
    """

    # Given: Invalid input
    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    # When: We instantiate the settings with invalid input data
    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    # Then: A ConfigValidationError is raised, caused by a pydantic validation error on the expected field
    assert "Error validating configuration" in str(err.value)
    assert field_name in str(err.value.__cause__)
