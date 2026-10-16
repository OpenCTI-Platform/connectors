import warnings
from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


def _fake_settings(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake config dict.
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
                    "name": "Google Safe Browsing",
                    "scope": "Url,Domain-Name,Hostname",
                    "log_level": "error",
                    "auto": True,
                    "max_tlp": "red",
                },
                "safe_browsing": {
                    "api_key": "test-api-key",
                    "api_url": "https://sba.yandex.net",
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
                "safe_browsing": {
                    "api_key": "test-api-key",
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
    settings = _fake_settings(settings_dict)()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.safe_browsing, BaseConfigModel) is True


def test_settings_defaults():
    settings = _fake_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {},
            "safe_browsing": {"api_key": "test-api-key"},
        }
    )()

    assert settings.connector.name == "Google Safe Browsing"
    assert settings.connector.scope == ["Url", "Domain-Name", "Hostname"]
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert str(settings.safe_browsing.api_url) == "https://safebrowsing.googleapis.com/"
    assert settings.connector.max_tlp == "amber"


def test_settings_empty_api_url_falls_back_to_default():
    settings = _fake_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {},
            "safe_browsing": {"api_key": "test-api-key", "api_url": ""},
        }
    )()

    assert str(settings.safe_browsing.api_url) == "https://safebrowsing.googleapis.com/"


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "safe_browsing": {"api_key": "test-api-key"},
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "safe_browsing": {"api_key": "test-api-key"},
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "safe_browsing": {},
            },
            id="missing_api_key",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "safe_browsing": {"api_key": ""},
            },
            id="empty_api_key",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"max_tlp": "invalid"},
                "safe_browsing": {"api_key": "test-api-key"},
            },
            id="invalid_max_tlp",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    with pytest.raises(ConfigValidationError) as err:
        _fake_settings(settings_dict)()
    assert "Error validating configuration" in str(err)


def test_settings_should_migrate_deprecated_google_safe_browsing_api_key():
    """The legacy `GOOGLE_SAFE_BROWSING_API_KEY` is used when `SAFE_BROWSING_API_KEY` is unset."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        settings = _fake_settings(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "google_safe_browsing": {"api_key": "legacy-api-key"},
            }
        )()

    assert settings.safe_browsing.api_key.get_secret_value() == "legacy-api-key"
    warning_messages = [str(warning.message) for warning in w]
    assert any("google_safe_browsing.api_key" in msg for msg in warning_messages)


def test_settings_should_prefer_new_api_key_over_deprecated_one():
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        settings = _fake_settings(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "safe_browsing": {"api_key": "new-api-key"},
                "google_safe_browsing": {"api_key": "legacy-api-key"},
            }
        )()

    assert settings.safe_browsing.api_key.get_secret_value() == "new-api-key"
