from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from settings import ConnectorSettings

MINIMAL_VALID_SETTINGS_DICT: dict[str, Any] = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {
        "id": "connector-id",
    },
    "s3": {
        "access_key_id": "test-access-key-id",
        "secret_access_key": "test-secret-access-key",
        "bucket_name": "test-bucket",
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
                    "name": "S3 Bucket",
                    "scope": "s3",
                    "log_level": "error",
                    "duration_period": "PT30S",
                },
                "s3": {
                    "access_key_id": "test-access-key-id",
                    "secret_access_key": "test-secret-access-key",
                    "bucket_name": "test-bucket",
                    "region": "eu-west-3",
                    "endpoint_url": "https://s3.example.org",
                    "bucket_prefixes": "ACI_TI, ACI_Vuln",
                    "author": "Test Author",
                    "marking": "TLP:AMBER",
                    "interval": 60,
                    "attach_original_file": True,
                    "delete_after_import": False,
                    "no_split_bundles": False,
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
    assert isinstance(settings.s3, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {},
            id="empty_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {
                    "id": "connector-id",
                },
                "s3": {
                    "access_key_id": "test-access-key-id",
                    "secret_access_key": "test-secret-access-key",
                    "bucket_name": "test-bucket",
                },
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": 12345,
                },
                "s3": {
                    "access_key_id": "test-access-key-id",
                    "secret_access_key": "test-secret-access-key",
                    "bucket_name": "test-bucket",
                },
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                },
                "s3": {
                    "access_key_id": "test-access-key-id",
                    "secret_access_key": "test-secret-access-key",
                },
            },
            id="missing_s3_bucket_name",
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
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but invalid config dict.
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

    assert settings.connector.id == "11d03c01-5469-43a8-bd2d-43f691934564"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_default_optional_fields():
    """
    Test that the optional fields mirroring the legacy `get_config_variable` defaults
    keep the very same default values.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert settings.connector.name == "S3 Bucket"
    assert settings.connector.scope == ["s3"]
    assert settings.connector.log_level == "error"
    assert settings.s3.region == "us-east-1"
    assert settings.s3.endpoint_url is None
    assert settings.s3.bucket_prefixes == ["ACI_TI", "ACI_Vuln"]
    assert settings.s3.author is None
    assert settings.s3.marking == "TLP:GREEN"
    assert settings.s3.interval == 30
    assert settings.s3.attach_original_file is False
    assert settings.s3.delete_after_import is True
    assert settings.s3.no_split_bundles is True


def test_settings_should_hide_secrets():
    """Test that the S3 credentials are wrapped in `SecretStr` and thus never leaked in logs."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(MINIMAL_VALID_SETTINGS_DICT)

    settings = FakeConnectorSettings()

    assert str(settings.s3.access_key_id) == "**********"
    assert str(settings.s3.secret_access_key) == "**********"
    assert settings.s3.access_key_id.get_secret_value() == "test-access-key-id"
    assert settings.s3.secret_access_key.get_secret_value() == "test-secret-access-key"
