from typing import Any

import pytest
from anyrun_task import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


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
                    "auto": True,
                },
                "anyrun": {
                    "token": "SecretStr",
                    "max_tlp": "TLP:AMBER",
                    "url": "https://api.any.run",
                    "timer": 42,
                    "os": "windows",
                    "privacy": "bylink",
                    "automated_interactivity": True,
                    "ioc": True,
                    "mitre": True,
                    "processes": True,
                    "task_timer": 60,
                    "os_bitness": "64",
                    "os_version": "10",
                    "os_locale": "en-US",
                    "os_browser": "Google Chrome",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "anyrun": {
                    "token": "SecretStr",
                    "max_tlp": "TLP:AMBER",
                    "url": "https://api.any.run",
                    "timer": 42,
                    "os": "windows",
                    "privacy": "bylink",
                    "automated_interactivity": True,
                    "ioc": True,
                    "mitre": True,
                    "processes": True,
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
    assert isinstance(settings.anyrun, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "anyrun": {
                    "token": "SecretStr",
                    "max_tlp": "TLP:AMBER",
                    "url": "https://api.any.run",
                    "timer": 42,
                    "os": "windows",
                    "privacy": "bylink",
                    "automated_interactivity": True,
                    "ioc": True,
                    "mitre": True,
                    "processes": True,
                    "task_timer": 60,
                    "os_bitness": "64",
                    "os_version": "10",
                    "os_locale": "en-US",
                    "os_browser": "Google Chrome",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                },
                "anyrun": {
                    "token": "SecretStr",
                    "max_tlp": "TLP:AMBER",
                    "url": "https://api.any.run",
                    "timer": 42,
                    "os": "windows",
                    "privacy": "bylink",
                    "automated_interactivity": True,
                    "ioc": True,
                    "mitre": True,
                    "processes": True,
                    "task_timer": 60,
                    "os_bitness": "64",
                    "os_version": "10",
                    "os_locale": "en-US",
                    "os_browser": "Google Chrome",
                },
            },
            "connector.id",
            id="invalid_connector_id",
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
