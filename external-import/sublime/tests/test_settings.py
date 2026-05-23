"""Tests for ConnectorSettings validation."""

from typing import Any

import pytest
from connector.settings import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "0a3a00ad-b5f0-4dca-83b6-9012662dcf80",
                    "name": "Sublime Security",
                    "scope": "sublime",
                    "log_level": "error",
                    "duration_period": "PT3M",
                },
                "sublime": {
                    "url": "https://platform.sublime.security",
                    "token": "my-secret-token",
                    "incident_type": "phishing",
                    "verdicts": "malicious,suspicious",
                    "tlp_level": "amber",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "sublime": {
                    "token": "my-secret-token",
                },
            },
            id="minimal_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "sublime": {
                    "token": "my-secret-token",
                    "auto_create_cases": True,
                    "set_priority": False,
                    "set_severity": False,
                    "batch_size": 50,
                    "force_historical": True,
                    "first_run_duration": "PT24H",
                    "tlp_level": "red",
                },
            },
            id="valid_settings_with_all_options",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "sublime": {
                    "token": "my-secret-token",
                    "verdicts": "malicious",
                    "tlp_level": "clear",
                },
            },
            id="valid_settings_with_single_verdict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` accepts valid input.
    `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.sublime, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "sublime": {"token": "my-secret-token"},
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "sublime": {"token": "my-secret-token"},
            },
            "connector.id",
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "sublime": {},
            },
            "sublime.token",
            id="missing_sublime_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "sublime": {
                    "token": "my-secret-token",
                    "url": "not-a-valid-url",
                },
            },
            "sublime.url",
            id="invalid_sublime_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "sublime": {
                    "token": "my-secret-token",
                    "tlp_level": "INVALID_TLP",
                },
            },
            "sublime.tlp_level",
            id="invalid_tlp_level",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` raises on invalid input.
    `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)
