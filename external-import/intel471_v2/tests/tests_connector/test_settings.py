from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from intel471 import ConnectorSettings

INITIAL_HISTORY_TIMESTAMP = 1696156471000  # 2023-10-01


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
                },
                "intel471": {
                    "api_username": "test-username",
                    "api_key": "test-api-key",
                    "interval_indicators": 60,
                    "initial_history_indicators": INITIAL_HISTORY_TIMESTAMP,
                    "interval_yara": 60,
                    "initial_history_yara": INITIAL_HISTORY_TIMESTAMP,
                    "interval_cves": 120,
                    "initial_history_cves": INITIAL_HISTORY_TIMESTAMP,
                    "interval_reports": 120,
                    "initial_history_reports": INITIAL_HISTORY_TIMESTAMP,
                    "proxy": None,
                    "ioc_score": 90,
                    "backend": "verity471",
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
                "connector": {},
                "intel471": {
                    "api_username": "test-username",
                    "api_key": "test-api-key",
                    "interval_indicators": 60,
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
    assert isinstance(settings.intel471, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "intel471": {
                    "api_username": "test-username",
                    "api_key": "test-api-key",
                    "interval_indicators": 60,
                    "initial_history_indicators": INITIAL_HISTORY_TIMESTAMP,
                    "interval_yara": 60,
                    "initial_history_yara": INITIAL_HISTORY_TIMESTAMP,
                    "interval_cves": 120,
                    "initial_history_cves": INITIAL_HISTORY_TIMESTAMP,
                    "interval_reports": 120,
                    "initial_history_reports": INITIAL_HISTORY_TIMESTAMP,
                    "proxy": None,
                    "ioc_score": 90,
                    "backend": "titan",
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
                },
                "intel471": {
                    "api_key": "test-api-key",
                    "interval_indicators": 60,
                    "initial_history_indicators": INITIAL_HISTORY_TIMESTAMP,
                    "interval_yara": 60,
                    "initial_history_yara": INITIAL_HISTORY_TIMESTAMP,
                    "interval_cves": 120,
                    "initial_history_cves": INITIAL_HISTORY_TIMESTAMP,
                    "interval_reports": 120,
                    "initial_history_reports": INITIAL_HISTORY_TIMESTAMP,
                    "proxy": None,
                    "ioc_score": 90,
                    "backend": "titan",
                },
            },
            "intel471.api_username",
            id="missing_intel471_api_username",
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

    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        FakeConnectorSettings()
