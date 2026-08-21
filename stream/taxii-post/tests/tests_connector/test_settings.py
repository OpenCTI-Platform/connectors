from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from taxii_post_connector import ConnectorSettings


def _full_valid_settings() -> dict[str, Any]:
    """Config dict with every field of `ConnectorSettings` explicitly set."""
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "name": "TAXII POST",
            "scope": "taxii",
            "log_level": "error",
            "live_stream_id": "live-stream-id",
            "live_stream_listen_delete": False,
            "live_stream_no_dependencies": False,
        },
        "taxii": {
            "url": "https://taxii.changeme.com",
            "ssl_verify": False,
            "api_root": "api-root",
            "collection_id": "collection-id",
            "token": "test-taxii-token",
            "login": "test-login",
            "password": "test-password",
            "version": "2.0",
            "stix_version": "2.0",
            "delete_created_by_ref": False,
            "delete_marking_definition": False,
        },
    }


def _minimal_valid_settings() -> dict[str, Any]:
    """Config dict with only the required fields, all others rely on their default."""
    return {
        "opencti": {
            "url": "http://localhost:8080",
            "token": "test-token",
        },
        "connector": {
            "id": "connector-id",
            "live_stream_id": "live-stream-id",
        },
        "taxii": {
            "url": "https://taxii.changeme.com",
            "collection_id": "collection-id",
            "token": "test-taxii-token",
        },
    }


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(_full_valid_settings(), id="full_valid_settings_dict"),
        pytest.param(_minimal_valid_settings(), id="minimal_valid_settings_dict"),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` can be instantiated from a valid config dict:
        - each config section MUST be an instance of `BaseConfigModel`
        - the values of the config dict MUST be correctly assigned to the settings' fields
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.taxii, BaseConfigModel) is True

    assert settings.connector.type == "STREAM"
    assert settings.connector.live_stream_id == "live-stream-id"
    assert settings.taxii.collection_id == "collection-id"
    assert str(settings.taxii.url) == "https://taxii.changeme.com/"


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            settings_dict = _minimal_valid_settings()
            settings_dict["connector"] = {"live_stream_id": "live-stream-id"}
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert settings.connector.id == "27a0802c-2a6d-4ecc-ac22-151e74d5cd18"
    assert UUID(settings.connector.id).version == 4


def test_settings_should_use_defaults_when_optional_fields_are_missing():
    """
    Test that the connector's defaults are applied when optional fields are not provided:
        - the connector section MUST fall back to the connector's own name/scope/log level
        - the TAXII section MUST fall back to the documented defaults
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_minimal_valid_settings())

    settings = FakeConnectorSettings()

    assert settings.connector.name == "TAXII POST"
    assert settings.connector.scope == ["taxii"]
    assert settings.connector.log_level == "error"
    assert settings.connector.live_stream_listen_delete is True
    assert settings.connector.live_stream_no_dependencies is True

    assert settings.taxii.ssl_verify is True
    assert settings.taxii.api_root == "root"
    assert settings.taxii.login is None
    assert settings.taxii.password is None
    assert settings.taxii.version == "2.1"
    assert settings.taxii.stix_version == "2.1"
    assert settings.taxii.delete_created_by_ref is True
    assert settings.taxii.delete_marking_definition is True


def test_settings_should_hide_secrets():
    """
    Test that sensitive TAXII fields are wrapped in `SecretStr`,
    i.e. their value is only readable through `get_secret_value()`.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(_full_valid_settings())

    settings = FakeConnectorSettings()

    assert str(settings.taxii.token) == "**********"
    assert settings.taxii.token.get_secret_value() == "test-taxii-token"
    assert str(settings.taxii.password) == "**********"
    assert settings.taxii.password.get_secret_value() == "test-password"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "live_stream_id": "live-stream-id",
                },
                "taxii": {
                    "url": "https://taxii.changeme.com",
                    "collection_id": "collection-id",
                },
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 1234, "live_stream_id": "live-stream-id"},
                "taxii": {
                    "url": "https://taxii.changeme.com",
                    "collection_id": "collection-id",
                },
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id"},
                "taxii": {
                    "url": "https://taxii.changeme.com",
                    "collection_id": "collection-id",
                },
            },
            id="missing_live_stream_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "live_stream_id": "live-stream-id",
                },
                "taxii": {"collection_id": "collection-id"},
            },
            id="missing_taxii_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "live_stream_id": "live-stream-id",
                },
                "taxii": {"url": "not-an-url", "collection_id": "collection-id"},
            },
            id="invalid_taxii_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "live_stream_id": "live-stream-id",
                },
                "taxii": {
                    "url": "https://taxii.changeme.com",
                    "collection_id": "collection-id",
                },
            },
            id="missing_taxii_auth",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "live_stream_id": "live-stream-id",
                },
                "taxii": {
                    "url": "https://taxii.changeme.com",
                    "collection_id": "collection-id",
                    "login": "test-login",
                },
            },
            id="missing_taxii_password",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "live_stream_id": "live-stream-id",
                },
                "taxii": {
                    "url": "https://taxii.changeme.com",
                    "collection_id": "collection-id",
                    "password": "test-password",
                },
            },
            id="missing_taxii_login",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` raises a `ConfigValidationError`
    when the config dict is missing required fields or holds invalid values.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)


@pytest.mark.parametrize(
    "taxii_auth",
    [
        pytest.param({"token": "test-taxii-token"}, id="token_only"),
        pytest.param(
            {"login": "test-login", "password": "test-password"},
            id="login_and_password_only",
        ),
    ],
)
def test_settings_should_accept_either_token_or_login_password(taxii_auth):
    """Test that `TaxiiConfig` accepts either `token` alone or `login`+`password` alone."""
    settings_dict = _minimal_valid_settings()
    settings_dict["taxii"] = {**settings_dict["taxii"], **taxii_auth}

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert (settings.taxii.token is not None) or (
        settings.taxii.login is not None and settings.taxii.password is not None
    )
