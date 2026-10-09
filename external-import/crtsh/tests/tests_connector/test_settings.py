from datetime import timedelta
from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "crtsh": {
        "domain": "example.com",
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
                    "name": "crt.sh",
                    "scope": "crtsh",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "crtsh": {
                    "domain": "example.com",
                    "labels": "crtsh,osint",
                    "marking_refs": "TLP:GREEN",
                    "is_expired": True,
                    "is_wildcard": True,
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
    assert isinstance(settings.crtsh, BaseConfigModel) is True


def test_settings_should_apply_defaults():
    """Test that optional fields fall back on the defaults of the legacy configuration."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.connector.name == "crt.sh"
    assert settings.connector.scope == ["crtsh"]
    assert settings.connector.log_level == "error"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert settings.crtsh.labels == ["crtsh", "osint"]
    assert settings.crtsh.marking_refs is None
    assert settings.crtsh.is_expired is False
    assert settings.crtsh.is_wildcard is False


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "342ecd95-7d1d-41d7-a2d7-595803bce18c"
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "crtsh": {"domain": "example.com"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "crtsh": {"domain": "example.com"},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "crtsh": {},
            },
            id="missing_crtsh_domain",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"run_every": "1 hour"},
                "crtsh": {"domain": "example.com"},
            },
            id="invalid_connector_run_every",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "crtsh": {"domain": "example.com", "marking_refs": "TLP:PURPLE"},
            },
            id="invalid_crtsh_marking_refs",
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
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake and invalid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    assert "Error validating configuration" in str(err.value)


@pytest.mark.parametrize(
    "run_every, expected",
    [
        ("30s", timedelta(seconds=30)),
        ("10m", timedelta(minutes=10)),
        ("12H", timedelta(hours=12)),
        ("7d", timedelta(days=7)),
    ],
)
def test_settings_should_migrate_deprecated_run_every(run_every, expected):
    """`CONNECTOR_RUN_EVERY` MUST be migrated to `CONNECTOR_DURATION_PERIOD`."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "connector": {"run_every": run_every},
                }
            )

    with pytest.warns(UserWarning, match="connector.run_every"):
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == expected


def test_settings_should_prefer_duration_period_over_deprecated_run_every():
    """`CONNECTOR_DURATION_PERIOD` MUST win when both variables are set."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    **MINIMAL_VALID_SETTINGS_DICT,
                    "connector": {"run_every": "7d", "duration_period": "PT2H"},
                }
            )

    with pytest.warns(UserWarning, match="Using only 'connector.duration_period'"):
        settings = FakeConnectorSettings()

    assert settings.connector.duration_period == timedelta(hours=2)
