from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr
from secops_siem_services.api_client import SCOPES, SecOpsEntitiesClient


def _service_account_config() -> SimpleNamespace:
    return SimpleNamespace(
        auth_method="service_account",
        project_id="test-project-id",
        project_instance="test-instance",
        project_region="us",
        private_key_id="test-key-id",
        private_key=SecretStr("test-private-key"),
        client_email="test@project.iam.gserviceaccount.com",
        client_id="123456789",
        auth_uri="https://accounts.google.com/o/oauth2/auth",
        token_uri="https://oauth2.googleapis.com/token",
        auth_provider_cert="https://www.googleapis.com/oauth2/v1/certs",
        client_cert_url="https://www.googleapis.com/robot/v1/metadata/x509/test",
    )


def _adc_config() -> SimpleNamespace:
    return SimpleNamespace(
        auth_method="adc",
        project_id="test-project-id",
        project_instance="test-instance",
        project_region="us",
        private_key_id=None,
        private_key=None,
        client_email=None,
        client_id=None,
        auth_uri="https://accounts.google.com/o/oauth2/auth",
        token_uri="https://oauth2.googleapis.com/token",
        auth_provider_cert="https://www.googleapis.com/oauth2/v1/certs",
        client_cert_url=None,
    )


@pytest.fixture
def mocked_google(mocker):
    """Mock Google auth entry points and the authorized session factory."""
    return SimpleNamespace(
        adc_default=mocker.patch(
            "secops_siem_services.api_client.google.auth.default",
            return_value=(MagicMock(name="adc_credentials"), "test-project-id"),
        ),
        from_sa_info=mocker.patch(
            "secops_siem_services.api_client.service_account.Credentials."
            "from_service_account_info",
            return_value=MagicMock(name="sa_credentials"),
        ),
        authorized_session=mocker.patch(
            "secops_siem_services.api_client.ChronicleRequests.AuthorizedSession",
            return_value=MagicMock(name="authorized_session"),
        ),
    )


def test_init_session_adc_uses_google_auth_default(mocked_google):
    client = SecOpsEntitiesClient(helper=MagicMock(), config=_adc_config())

    mocked_google.adc_default.assert_called_once_with(scopes=SCOPES)
    mocked_google.from_sa_info.assert_not_called()
    mocked_google.authorized_session.assert_called_once_with(
        credentials=mocked_google.adc_default.return_value[0],
        refresh_status_codes=[401],
        max_refresh_attempts=3,
    )
    assert (
        client.chronicle_http_session is mocked_google.authorized_session.return_value
    )


def test_init_session_service_account_uses_from_service_account_info(mocked_google):
    config = _service_account_config()

    SecOpsEntitiesClient(helper=MagicMock(), config=config)

    mocked_google.adc_default.assert_not_called()
    mocked_google.from_sa_info.assert_called_once()
    _, call_kwargs = mocked_google.from_sa_info.call_args
    assert call_kwargs["scopes"] == SCOPES
    info = call_kwargs["info"]
    assert info["type"] == "service_account"
    assert info["private_key"] == "test-private-key"
    assert info["client_email"] == config.client_email
    mocked_google.authorized_session.assert_called_once_with(
        credentials=mocked_google.from_sa_info.return_value,
        refresh_status_codes=[401],
        max_refresh_attempts=3,
    )
