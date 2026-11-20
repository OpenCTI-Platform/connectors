from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import ConfigValidationError


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


def test_settings_accepts_tlp_level():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "scope": "intrusion-set",
                        "tlp_level": "amber+strict",
                    },
                    "rst_threat_library": {
                        "baseurl": "http://test.com",
                        "apikey": "test-api-key",
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.connector.tlp_level == "amber+strict"
    assert settings.to_helper_config()["connector"]["tlp_level"] == "amber+strict"


def test_settings_rejects_unknown_tlp_level():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "scope": "intrusion-set",
                        "tlp_level": "black",
                    },
                    "rst_threat_library": {
                        "baseurl": "http://test.com",
                        "apikey": "test-api-key",
                    },
                }
            )

    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()


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
