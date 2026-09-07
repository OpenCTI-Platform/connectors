from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError
from pydantic import ValidationError


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
                    "name": "Doppel Alert and Takedown",
                    "scope": "Url,Domain-Name",
                    "log_level": "error",
                    "auto": True,
                },
                "doppel_alert_takedown": {
                    "api_base_url": "https://api.doppel.com",
                    "api_key": "test-api-key",
                    "user_api_key": "test-user-api-key",
                    "tags": ["test", "poc"],
                    "takedown_comment": "Confirmed phishing.",
                    "max_tlp": "TLP:CLEAR",
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
                    "id": "connector-id",
                    "scope": "Url,Domain-Name",
                },
                "doppel_alert_takedown": {
                    "api_key": "test-api-key",
                    "user_api_key": "test-user-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Url,Domain-Name",
                },
                "doppel_alert_takedown": {
                    "api_version": "v2",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            id="valid_v2_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.doppel_alert_takedown, BaseConfigModel) is True


def test_settings_should_split_comma_separated_tags():
    """Tags provided as a comma-separated string should be parsed into a list."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {
                        "id": "connector-id",
                        "scope": "Url,Domain-Name",
                    },
                    "doppel_alert_takedown": {
                        "api_key": "test-api-key",
                        "user_api_key": "test-user-api-key",
                        "tags": "test, filigran-poc ,phishing",
                    },
                }
            )

    settings = FakeConnectorSettings()
    assert settings.doppel_alert_takedown.tags == ["test", "filigran-poc", "phishing"]


@pytest.mark.parametrize(
    "settings_dict, expected_error",
    [
        pytest.param(
            {},
            "url\n  Field required",
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Url,Domain-Name",
                },
                "doppel_alert_takedown": {
                    "api_key": "test-api-key",
                },
            },
            "user_api_key is required",
            id="missing_user_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Url,Domain-Name",
                },
                "doppel_alert_takedown": {
                    "api_version": "v2",
                    "client_id": "test-client-id",
                },
            },
            "client_secret is required",
            id="missing_v2_client_secret",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Url,Domain-Name",
                },
                "doppel_alert_takedown": {
                    "api_version": "v1",
                    "api_key": "test-api-key",
                    "user_api_key": "test-user-api-key",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            "V2 OAuth settings must be unset",
            id="mixed_v1_and_v2_credentials_in_v1_mode",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Url,Domain-Name",
                },
                "doppel_alert_takedown": {
                    "api_version": "v2",
                    "api_key": "test-api-key",
                    "user_api_key": "test-user-api-key",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                },
            },
            "V1 API key settings must be unset",
            id="mixed_v1_and_v2_credentials_in_v2_mode",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, expected_error):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err.value)

    validation_error = err.value.__cause__
    assert isinstance(validation_error, ValidationError)
    assert expected_error in str(validation_error)
