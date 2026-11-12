from typing import Any
from uuid import UUID

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {},
    "domaintools": {
        "api_base_url": "https://api.domaintools.com/v1/iris-detect/",
        "api_key": "test-api-key",
    },
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-detect/",
                    "api_key": "test-api-key",
                    "monitor_id": "test-monitor-id",
                    "store_iris_data": True,
                    "preview": False,
                    "tlp_level": "clear",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            MINIMAL_VALID_SETTINGS_DICT,
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
    assert isinstance(settings.domaintools, BaseConfigModel) is True

    if settings_dict == MINIMAL_VALID_SETTINGS_DICT:
        assert settings.connector.name == "DomainToolsIrisDetectConnector"
        assert settings.connector.scope == ["stix2"]
        assert settings.to_helper_config()["connector"]["scope"] == "stix2"
        assert settings.connector.log_level == "error"
        assert settings.connector.duration_period.total_seconds() == 3600
        assert settings.domaintools.monitor_id is None
        assert settings.domaintools.store_iris_data is False
        assert settings.domaintools.preview is False
        assert settings.domaintools.tlp_level == "clear"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-detect/",
                    "api_key": "test-api-key",
                },
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-detect/",
                    "api_key": "test-api-key",
                },
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-detect/"
                },
            },
            id="missing_domaintools_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
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
    assert "Error validating configuration" in str(err.value)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "76db5e8d-8633-4e32-9a4c-53c4e5eb56ef"
    assert UUID(settings.connector.id).version == 4
