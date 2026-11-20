from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from connector import ConnectorSettings
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
                    "duration_period": "PT5M",
                },
                "urlhaus_recent_payloads": {
                    "api_url": "https://urlhaus-api.abuse.ch/v1/",
                    "auth_key": "test-auth-key",
                    "cooldown_seconds": 300,
                    "include_filetypes": "exe,zip,dll,docm,docx,doc,xls,xlsx,xlsm,js,xll",
                    "include_signatures": "",
                    "skip_unknown_filetypes": True,
                    "skip_null_signature": True,
                    "labels": "urlhaus",
                    "labels_color": "#54483b",
                    "signature_label_color": "#0059f7",
                    "filetype_label_color": "#54483b",
                },
            },
            id="full_valid_settings_dict",
        ),
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
                "urlhaus_recent_payloads": {
                    "api_url": "https://urlhaus-api.abuse.ch/v1/",
                    "auth_key": "test-auth-key",
                    "cooldown_seconds": 300,
                    "skip_unknown_filetypes": True,
                    "skip_null_signature": True,
                    "labels": "urlhaus",
                    "labels_color": "#54483b",
                    "signature_label_color": "#0059f7",
                    "filetype_label_color": "#54483b",
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
    assert isinstance(settings.urlhaus_recent_payloads, BaseConfigModel) is True


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
                    "duration_period": "PT5M",
                },
                "urlhaus_recent_payloads": {
                    "api_url": "https://urlhaus-api.abuse.ch/v1/",
                    "auth_key": "test-auth-key",
                    "cooldown_seconds": 300,
                    "include_filetypes": "exe,zip,dll,docm,docx,doc,xls,xlsx,xlsm,js,xll",
                    "include_signatures": "",
                    "skip_unknown_filetypes": True,
                    "skip_null_signature": True,
                    "labels": "urlhaus",
                    "labels_color": "#54483b",
                    "signature_label_color": "#0059f7",
                    "filetype_label_color": "#54483b",
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
                    "duration_period": "PT5M",
                },
                "urlhaus_recent_payloads": {
                    "api_url": "https://urlhaus-api.abuse.ch/v1/",
                    "auth_key": "test-auth-key",
                    "cooldown_seconds": 300,
                    "include_filetypes": "exe,zip,dll,docm,docx,doc,xls,xlsx,xlsm,js,xll",
                    "include_signatures": "",
                    "skip_unknown_filetypes": True,
                    "skip_null_signature": True,
                    "labels": "urlhaus",
                    "labels_color": "#54483b",
                    "signature_label_color": "#0059f7",
                    "filetype_label_color": "#54483b",
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


def _build_settings(urlhaus_section: dict):
    """Build a `ConnectorSettings` from a fake config whose connector section is `urlhaus_section`."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "name": "Test Connector",
                        "scope": "test, connector",
                        "log_level": "error",
                        "duration_period": "PT5M",
                    },
                    "urlhaus_recent_payloads": urlhaus_section,
                }
            )

    return FakeConnectorSettings()


def test_settings_should_accept_community_auth_key_only():
    section = _build_settings({"auth_key": "test-auth-key"}).urlhaus_recent_payloads

    assert section.auth_key.get_secret_value() == "test-auth-key"
    assert section.community_configured is True
    assert section.commercial_configured is False
    assert section.use_commercial is False


def test_settings_should_accept_spamhaus_credentials_only():
    section = _build_settings(
        {"spamhaus_username": "user@example.com", "spamhaus_password": "s3cret"}
    ).urlhaus_recent_payloads

    assert section.auth_key is None
    assert section.spamhaus_username.get_secret_value() == "user@example.com"
    assert section.spamhaus_password.get_secret_value() == "s3cret"
    assert section.use_commercial is True


def test_settings_should_prefer_commercial_mode_when_both_are_configured():
    section = _build_settings(
        {
            "auth_key": "test-auth-key",
            "spamhaus_username": "user@example.com",
            "spamhaus_password": "s3cret",
        }
    ).urlhaus_recent_payloads

    assert section.use_commercial is True
    assert section.community_configured is True  # kept as the fallback


def test_settings_should_migrate_the_deprecated_api_key_to_auth_key():
    with pytest.warns(UserWarning, match="api_key"):
        section = _build_settings({"api_key": "legacy-key"}).urlhaus_recent_payloads

    assert section.auth_key.get_secret_value() == "legacy-key"


def test_settings_should_not_expose_spamhaus_secrets_in_repr():
    settings = _build_settings(
        {"spamhaus_username": "user@example.com", "spamhaus_password": "s3cret"}
    )

    assert "s3cret" not in repr(settings)
    assert "user@example.com" not in repr(settings)


def test_settings_should_raise_naming_both_options_when_no_auth_mode_is_configured():
    with pytest.raises(ConfigValidationError) as err:
        _build_settings({})

    cause = str(err.value.__cause__)
    assert "URLHAUS_RECENT_PAYLOADS_AUTH_KEY" in cause
    assert "URLHAUS_RECENT_PAYLOADS_SPAMHAUS_USERNAME" in cause
    assert "URLHAUS_RECENT_PAYLOADS_SPAMHAUS_PASSWORD" in cause


@pytest.mark.parametrize(
    "credentials",
    [
        pytest.param({"spamhaus_username": "user@example.com"}, id="username_only"),
        pytest.param({"spamhaus_password": "s3cret"}, id="password_only"),
        pytest.param(
            {"auth_key": "test-auth-key", "spamhaus_username": "user@example.com"},
            id="username_only_with_auth_key",
        ),
    ],
)
def test_settings_should_raise_when_spamhaus_credentials_are_incomplete(credentials):
    with pytest.raises(ConfigValidationError) as err:
        _build_settings(credentials)

    cause = str(err.value.__cause__)
    assert "URLHAUS_RECENT_PAYLOADS_SPAMHAUS_USERNAME" in cause
    assert "URLHAUS_RECENT_PAYLOADS_SPAMHAUS_PASSWORD" in cause
    assert "s3cret" not in cause
    assert "user@example.com" not in cause


def test_settings_import_start_date_defaults_to_one_day_ago():
    section = _build_settings({"auth_key": "test-auth-key"}).urlhaus_recent_payloads

    expected = datetime.now(timezone.utc) - timedelta(days=1)
    assert abs(section.import_start_date - expected) < timedelta(minutes=1)


def test_settings_import_start_date_accepts_an_iso_datetime():
    section = _build_settings(
        {"auth_key": "test-auth-key", "import_start_date": "2026-11-01T00:00:00Z"}
    ).urlhaus_recent_payloads

    assert section.import_start_date == datetime(2026, 11, 1, tzinfo=timezone.utc)
