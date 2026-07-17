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
                    "name": "Doppel Alert and Takedown",
                    "scope": "Url,Domain-Name",
                    "log_level": "error",
                    "auto": True,
                },
                "doppel": {
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
                "doppel": {
                    "api_key": "test-api-key",
                    "user_api_key": "test-user-api-key",
                },
            },
            id="minimal_valid_settings_dict",
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
    assert isinstance(settings.doppel, BaseConfigModel) is True


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
                    "doppel": {
                        "api_key": "test-api-key",
                        "user_api_key": "test-user-api-key",
                        "tags": "test, filigran-poc ,phishing",
                    },
                }
            )

    settings = FakeConnectorSettings()
    assert settings.doppel.tags == ["test", "filigran-poc", "phishing"]


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
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "scope": "Url,Domain-Name",
                },
                "doppel": {
                    "api_key": "test-api-key",
                },
            },
            "doppel.user_api_key",
            id="missing_user_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "scope": "Url,Domain-Name",
                },
                "doppel": {
                    "api_key": "test-api-key",
                    "user_api_key": "test-user-api-key",
                },
            },
            "connector.id",
            id="missing_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
