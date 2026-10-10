from typing import Any
from uuid import UUID

import pytest
from connector.settings import ConnectorSettings
from connectors_sdk import ConfigValidationError

CONNECTOR_DEFAULT_ID = "848e59be-6d88-400f-a707-2a678c76927f"

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "ismalicious": {
        "api_key": "test-api-key",
    },
}


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
                    "scope": "IPv4-Addr,Domain-Name",
                    "log_level": "error",
                    "auto": True,
                },
                "ismalicious": {
                    "api_url": "https://api.example.com",
                    "api_key": "test-api-key",
                    "max_tlp": "TLP:RED",
                    "enrich_ipv4": False,
                    "enrich_ipv6": False,
                    "enrich_domain": False,
                    "min_score": 50,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For more details about common settings, see `BaseConnectorSettings` tests in `connectors-sdk`.
    """

    class FakeConnectorSettings(ConnectorSettings):
        """Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert settings.opencti is not None
    assert settings.connector is not None
    assert settings.ismalicious is not None


def test_settings_should_apply_defaults():
    """Optional fields fall back on the connector's historical defaults."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.name == "isMalicious"
    assert settings.connector.scope == ["IPv4-Addr", "IPv6-Addr", "Domain-Name"]
    assert settings.connector.log_level == "info"
    assert settings.connector.auto is False
    assert settings.ismalicious.api_url == "https://api.ismalicious.com"
    assert settings.ismalicious.api_key.get_secret_value() == "test-api-key"
    assert settings.ismalicious.max_tlp == "TLP:AMBER"
    assert settings.ismalicious.enrich_ipv4 is True
    assert settings.ismalicious.enrich_ipv6 is True
    assert settings.ismalicious.enrich_domain is True
    assert settings.ismalicious.min_score == 0


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {},
                "ismalicious": {"api_key": "test-api-key"},
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
                "connector": {"id": 123456},
                "ismalicious": {"api_key": "test-api-key"},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "ismalicious": {},
            },
            "ismalicious.api_key",
            id="missing_ismalicious_api_key",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "ismalicious": {"api_key": "test-api-key", "max_tlp": "amber"},
            },
            "ismalicious.max_tlp",
            id="invalid_ismalicious_max_tlp",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For more details about common settings, see `BaseConnectorSettings` tests in `connectors-sdk`.
    """

    class FakeConnectorSettings(ConnectorSettings):
        """Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake and invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == CONNECTOR_DEFAULT_ID
    assert UUID(settings.connector.id).version == 4
