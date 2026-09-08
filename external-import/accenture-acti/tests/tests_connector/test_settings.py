from typing import Any
from uuid import UUID

import pytest
from accenture_connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {},
    "accenture_acti": {
        "username": "test-username",
        "password": "test-password",
        "user_pool_id": "test-user-pool-id",
        "client_id": "test-client-id",
        "s3_bucket_name": "test-bucket",
        "s3_bucket_region": "eu-west-1",
        "s3_bucket_access_key": "test-access-key",
        "s3_bucket_secret_key": "test-secret-key",
    },
}

FULL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
    "connector": {
        "id": "connector-id",
        "name": "Test Connector",
        "scope": "test, connector",
        "log_level": "error",
        "duration_period": "PT5M",
    },
    "accenture_acti": {
        "username": "test-username",
        "password": "test-password",
        "user_pool_id": "test-user-pool-id",
        "client_id": "test-client-id",
        "s3_bucket_name": "test-bucket",
        "s3_bucket_region": "eu-west-1",
        "s3_bucket_access_key": "test-access-key",
        "s3_bucket_secret_key": "test-secret-key",
        "tlp_level": "amber+strict",
        "relative_import_start_date": "P30D",
        "threat_actor_as_intrusion_set": True,
    },
}


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(FULL_VALID_SETTINGS_DICT, id="full_valid_settings_dict"),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
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
    assert isinstance(settings.accenture_acti, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                **FULL_VALID_SETTINGS_DICT,
                "opencti": {"url": "http://localhost:8080"},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                **FULL_VALID_SETTINGS_DICT,
                "connector": {**FULL_VALID_SETTINGS_DICT["connector"], "id": 123456},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                **FULL_VALID_SETTINGS_DICT,
                "accenture_acti": {
                    **FULL_VALID_SETTINGS_DICT["accenture_acti"],
                    "tlp_level": "unknown",
                },
            },
            "accenture_acti.tlp_level",
            id="invalid_tlp_level",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param field_name: The name of the invalid field
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
    assert "Error validating configuration" in str(err)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler({**MINIMAL_VALID_SETTINGS_DICT, "connector": {}})

    settings = FakeConnectorSettings()

    assert settings.connector.id == "358f9d75-bcca-4be9-867c-6692552d3f74"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_expose_taxonomy_mapping():
    """The taxonomy mapping bundled with the connector MUST be exposed through the settings."""

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert isinstance(settings.mapping, dict)
    assert "France" in settings.mapping
