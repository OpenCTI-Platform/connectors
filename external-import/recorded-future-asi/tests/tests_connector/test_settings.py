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
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "recorded_future_asi": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                    "project_id": "test-project-id",
                    "tlp_level": "clear",
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
                    "scope": "test, connector",
                },
                "recorded_future_asi": {
                    "api_key": "test-api-key",
                    "project_id": "test-project-id",
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
    assert isinstance(settings.recorded_future_asi, BaseConfigModel) is True


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
                    "url": "http://localhost:PORT",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "recorded_future_asi": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                    "project_id": "test-project-id",
                    "tlp_level": "clear",
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
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "recorded_future_asi": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                    "project_id": "test-project-id",
                    "tlp_level": "clear",
                },
            },
            "connector.id",
            id="missing_connector_id",
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
                    "duration_period": "PT5M",
                },
                "recorded_future_asi": {
                    "api_base_url": "http://test.com",
                    "api_key": "test-api-key",
                    "tlp_level": "clear",
                },
            },
            "recorded_future_asi.project_id",
            id="missing_project_id",
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


def test_recorded_future_asi_retry_settings_defaults():
    settings_dict = {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "scope": "test, connector",
        },
        "recorded_future_asi": {
            "api_key": "test-api-key",
            "project_id": "test-project-id",
        },
    }

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert settings.recorded_future_asi.retry_max_attempts == 3
    assert settings.recorded_future_asi.retry_initial_seconds == 1
    assert settings.recorded_future_asi.retry_max_seconds == 60


def _make_fake_connector_settings(settings_dict: dict[str, Any]) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def _base_valid_settings_dict(**recorded_future_asi_overrides: Any) -> dict[str, Any]:
    recorded_future_asi = {
        "api_key": "test-api-key",
        "project_id": "test-project-id",
    }
    recorded_future_asi.update(recorded_future_asi_overrides)
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "scope": "test, connector",
        },
        "recorded_future_asi": recorded_future_asi,
    }


@pytest.mark.parametrize(
    "recorded_future_asi_overrides",
    [
        pytest.param({"filter_severity_min": "critical"}, id="filter_severity_min"),
        pytest.param({"filter_severity_exact": "moderate"}, id="filter_severity_exact"),
    ],
)
def test_settings_should_accept_valid_severity_filters(recorded_future_asi_overrides):
    settings = _make_fake_connector_settings(
        _base_valid_settings_dict(**recorded_future_asi_overrides)
    )

    for key, value in recorded_future_asi_overrides.items():
        assert getattr(settings.recorded_future_asi, key) == value


def test_settings_should_reject_both_severity_filters():
    with pytest.raises(ConfigValidationError) as err:
        _make_fake_connector_settings(
            _base_valid_settings_dict(
                filter_severity_min="critical",
                filter_severity_exact="moderate",
            )
        )
    assert str("Error validating configuration") in str(err)
