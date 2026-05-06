from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from secops_siem_connector import ConnectorSettings


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "google-secops-siem",
                    "log_level": "error",
                    "live_stream_id": "A2626721-31ED-441E-9C87-28AD1139D2AB",
                    "live_stream_listen_delete": True,
                    "live_stream_no_dependencies": True,
                },
                "secops_siem": {
                    "project_id": "test-project-id",
                    "project_instance": "test-instance",
                    "project_region": "us",
                    "private_key_id": "test-key-id",
                    "private_key": "test-private-key",
                    "client_email": "test@project.iam.gserviceaccount.com",
                    "client_id": "123456789",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_cert": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "google-secops-siem",
                    "log_level": "error",
                    "live_stream_id": "D5685291-70A3-47D2-AB3A-FEB0F7DA9257",
                },
                "secops_siem": {
                    "project_id": "test-project-id",
                    "project_instance": "test-instance",
                    "private_key_id": "test-key-id",
                    "private_key": "test-private-key",
                    "client_email": "test@project.iam.gserviceaccount.com",
                    "client_id": "123456789",
                    "client_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test",
                },
            },
            id="minimal_valid_settings_dict_uses_defaults",
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
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.secops_siem, BaseConfigModel) is True


def test_settings_should_normalize_escaped_private_key_newlines():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {
                        "id": "connector-id",
                        "scope": "google-secops-siem",
                        "log_level": "error",
                        "live_stream_id": "D5685291-70A3-47D2-AB3A-FEB0F7DA9257",
                    },
                    "secops_siem": {
                        "project_id": "test-project-id",
                        "project_instance": "test-instance",
                        "private_key_id": "test-key-id",
                        "private_key": "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\\n",
                        "client_email": "test@project.iam.gserviceaccount.com",
                        "client_id": "123456789",
                        "client_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test",
                    },
                }
            )

    settings = FakeConnectorSettings()
    private_key = settings.secops_siem.private_key.get_secret_value()

    assert "\\n" not in private_key
    assert "\n" in private_key


@pytest.mark.parametrize(
    "settings_dict, field_name",
    [
        pytest.param({}, "settings", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:PORT", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "google-secops-siem",
                    "log_level": "error",
                    "live_stream_id": "A2626721-31ED-441E-9C87-28AD1139D2AB",
                },
                "secops_siem": {
                    "project_id": "test-project-id",
                    "project_instance": "test-instance",
                    "private_key_id": "test-key-id",
                    "private_key": "test-private-key",
                    "client_email": "test@project.iam.gserviceaccount.com",
                    "client_id": "123456789",
                    "client_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test",
                },
            },
            "opencti.url",
            id="invalid_opencti_url",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "google-secops-siem",
                    "log_level": "error",
                    "live_stream_id": "A2626721-31ED-441E-9C87-28AD1139D2AB",
                },
                "secops_siem": {
                    "project_instance": "test-instance",
                    "private_key_id": "test-key-id",
                    "private_key": "test-private-key",
                    "client_email": "test@project.iam.gserviceaccount.com",
                    "client_id": "123456789",
                    "client_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test",
                },
            },
            "secops_siem.project_id",
            id="missing_project_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "scope": "google-secops-siem",
                    "log_level": "error",
                    "live_stream_id": "A2626721-31ED-441E-9C87-28AD1139D2AB",
                },
                "secops_siem": {
                    "project_id": "test-project-id",
                    "project_instance": "test-instance",
                    "private_key_id": "test-key-id",
                    "private_key": "test-private-key",
                    "client_email": "test@project.iam.gserviceaccount.com",
                    "client_id": "123456789",
                },
            },
            "secops_siem.client_cert_url",
            id="missing_client_cert_url",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, field_name):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict.

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(
        ConfigValidationError, match=r".*Error validating configuration.*"
    ):
        FakeConnectorSettings()
