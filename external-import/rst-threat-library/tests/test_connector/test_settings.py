from typing import Any

import pytest
from connectors_sdk import ConfigValidationError

from connector import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RST Threat Library",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "rst_threat_library": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "scope": "test, connector"},
                "rst_threat_library": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict: dict[str, Any]):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert settings.opencti is not None
    assert settings.connector is not None
    assert settings.rst_threat_library is not None


def test_settings_passes_auto_create_service_account_to_helper_config():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "name": "RST Threat Library",
                        "scope": "intrusion-set",
                        "log_level": "error",
                        "duration_period": "PT5M",
                        "auto_create_service_account": True,
                        "auto_create_service_account_confidence_level": 80,
                    },
                    "rst_threat_library": {
                        "baseurl": "http://test.com",
                        "apikey": "test-api-key",
                    },
                }
            )

    settings = FakeConnectorSettings()
    helper_config = settings.to_helper_config()

    assert helper_config["connector"]["auto_create_service_account"] is True
    assert (
        helper_config["connector"]["auto_create_service_account_confidence_level"]
        == 80
    )


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
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "RST Threat Library",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "rst_threat_library": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"name": "RST Threat Library", "scope": "test, connector"},
                "rst_threat_library": {
                    "baseurl": "http://test.com",
                    "apikey": "test-api-key",
                },
            },
            "connector.id",
            id="missing_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(
    settings_dict: dict[str, Any],
    field_name: str,
):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    assert "Error validating configuration" in str(err.value)


def test_settings_rejects_negative_retry():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "scope": "intrusion-set",
                    },
                    "rst_threat_library": {
                        "baseurl": "http://test.com",
                        "apikey": "test-api-key",
                        "retry": -1,
                    },
                }
            )

    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
