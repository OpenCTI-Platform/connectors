from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from freezegun import freeze_time

from dragos.settings import ConnectorSettings


def fake_connector_settings(settings_dict: dict[str, dict]) -> type[ConnectorSettings]:
    """Return a fake implementation of `ConnectorSettings` loading the given `settings_dict`."""

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings


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
                "dragos": {
                    "api_base_url": "http://test.com",
                    "api_token": "dragos_token",
                    "api_secret": "dragos_secret",
                    "import_start_date": "2023-01-01T00:00:00Z",
                    "tlp_level": "amber",
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
                "dragos": {
                    "api_base_url": "http://test.com",
                    "api_token": "dragos_token",
                    "api_secret": "dragos_secret",
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

    FakeConnectorSettings = fake_connector_settings(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.dragos, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "dragos": {
                    "api_base_url": "http://test.com",
                    "api_token": "dragos_token",
                    "api_secret": "dragos_secret",
                    "import_start_date": "P30D",
                },
            },
            id="relative_import_start_date",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "dragos": {
                    "api_base_url": "http://test.com",
                    "api_token": "dragos_token",
                    "api_secret": "dragos_secret",
                    "import_start_date": "P30D",
                },
            },
            id="absolute_import_start_date",
        ),
    ],
)
@freeze_time("2010-01-01T01:00:00", tz_offset=2)  # CEST
def test_settings_should_accept_both_relative_and_absolute_import_start_date(
    settings_dict,
):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    FakeConnectorSettings = fake_connector_settings(settings_dict)

    settings = FakeConnectorSettings()

    assert settings.dragos.import_start_date == (
        datetime.now(tz=timezone.utc) - timedelta(days=30)
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
                "dragos": {
                    "api_base_url": "http://test.com",
                    "api_token": "dragos_token",
                    "api_secret": "dragos_secret",
                    "import_start_date": "2023-01-01T00:00:00Z",
                    "tlp_level": "amber",
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
                    "duration_period": "PT5M",
                },
                "dragos": {
                    "api_base_url": "http://test.com",
                    "api_secret": "dragos_secret",
                    "import_start_date": "2023-01-01T00:00:00Z",
                    "tlp_level": "amber",
                },
            },
            "dragos.api_token",
            id="missing_dragos_api_token",
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

    FakeConnectorSettings = fake_connector_settings(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert str("Error validating configuration") in str(err)
