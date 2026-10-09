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
                    "scope": "Artifact,Url,StixFile,File",
                    "log_level": "error",
                    "max_tlp": "TLP:AMBER",
                },
                "reversinglabs_spectra_intel_submission": {
                    "url": "data.reversinglabs.com",
                    "username": "test-user",
                    "password": "test-password",
                    "sandbox_os": "windows10",
                    "sandbox_internet_sim": False,
                    "create_indicators": True,
                    "poll_interval": 250,
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
                "reversinglabs_spectra_intel_submission": {
                    "username": "test-user",
                    "password": "test-password",
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """Test that ConnectorSettings accepts valid input."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert (
        isinstance(settings.reversinglabs_spectra_intel_submission, BaseConfigModel)
        is True
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
                    "url": "http://localhost:8080",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "Artifact,Url,StixFile,File",
                    "log_level": "error",
                },
                "reversinglabs_spectra_intel_submission": {
                    "username": "test-user",
                    "password": "test-password",
                },
            },
            "opencti.token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "Artifact,Url,StixFile,File",
                    "log_level": "error",
                },
                "reversinglabs_spectra_intel_submission": {
                    "username": "test-user",
                    "password": "test-password",
                },
            },
            "connector.id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """Test that ConnectorSettings raises ConfigValidationError on invalid input."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as exc_info:
        FakeConnectorSettings()

    assert "Error validating configuration" in str(exc_info.value)


def test_settings_should_migrate_deprecated_max_tlp_to_connector_max_tlp():
    """
    Test that the deprecated `reversinglabs_spectra_intel_submission.max_tlp`
    (`REVERSINGLABS_SPECTRA_INTEL_SUBMISSION_MAX_TLP`) is migrated to `connector.max_tlp` (`CONNECTOR_MAX_TLP`).
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "reversinglabs_spectra_intel_submission": {
                        "username": "test-user",
                        "password": "test-password",
                        "max_tlp": "TLP:RED",
                    },
                }
            )

    with pytest.warns(
        UserWarning, match="reversinglabs_spectra_intel_submission.max_tlp"
    ):
        settings = FakeConnectorSettings()

    assert settings.connector.max_tlp == "TLP:RED"
