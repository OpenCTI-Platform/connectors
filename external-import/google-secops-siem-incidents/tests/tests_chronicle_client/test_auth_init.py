"""RED tests — Chronicle connector authentication and initialization.

Tests that GoogleSecOpsApiClient initialises with Google service-account
credentials and that the GoogleAuthHook refreshes / reuses them correctly.
"""

from unittest.mock import MagicMock, patch

import pytest
from google_secops_siem_incidents.client_api import GoogleSecOpsApiClient

from tests.tests_chronicle_client.factories import make_config


# ---------------------------------------------------------------------------
# Scenario: Successful initialization with valid credentials
# ---------------------------------------------------------------------------
@patch("google_secops_siem_incidents.client_api.Credentials.from_service_account_info")
def test_successful_initialization_with_valid_credentials(mock_from_sa):
    """A valid service-account config produces a ready client with auth hook."""

    def _given_valid_config():
        mock_creds = MagicMock()
        mock_creds.valid = True
        mock_from_sa.return_value = mock_creds
        return make_config()

    def _when_client_is_initialized(config):
        return GoogleSecOpsApiClient(config=config)

    def _then_client_is_ready(client):
        assert client is not None
        mock_from_sa.assert_called_once()

    config = _given_valid_config()
    client = _when_client_is_initialized(config)
    _then_client_is_ready(client)


# ---------------------------------------------------------------------------
# Scenario: Expired credentials are refreshed before a request is sent
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@patch("google_secops_siem_incidents.client_api.Request")
@patch("google_secops_siem_incidents.client_api.Credentials.from_service_account_info")
async def test_expired_credentials_are_refreshed(mock_from_sa, mock_request_cls):
    """Expired creds trigger a refresh and inject a Bearer header."""

    def _given_expired_credentials():
        mock_creds = MagicMock()
        mock_creds.valid = False
        mock_creds.token = "refreshed-token"
        mock_from_sa.return_value = mock_creds
        return mock_creds

    def _given_auth_hook(creds):
        with patch(
            "google_secops_siem_incidents.client_api.Credentials.from_service_account_info",
            return_value=creds,
        ):
            client = GoogleSecOpsApiClient(config=make_config())
        return client._auth_hook

    async def _when_before_hook_is_called(hook):
        request = MagicMock()
        request.headers = {}
        await hook.before(request)
        return request

    def _then_credentials_refreshed_and_header_set(creds, request):
        creds.refresh.assert_called_once()
        assert "Authorization" in request.headers
        assert request.headers["Authorization"].startswith("Bearer ")

    creds = _given_expired_credentials()
    hook = _given_auth_hook(creds)
    request = await _when_before_hook_is_called(hook)
    _then_credentials_refreshed_and_header_set(creds, request)


# ---------------------------------------------------------------------------
# Scenario: Valid credentials are reused without refresh
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@patch("google_secops_siem_incidents.client_api.Request")
@patch("google_secops_siem_incidents.client_api.Credentials.from_service_account_info")
async def test_valid_credentials_are_reused_without_refresh(
    mock_from_sa, mock_request_cls
):
    """Still-valid creds are not refreshed but the Bearer header is still set."""

    def _given_valid_credentials():
        mock_creds = MagicMock()
        mock_creds.valid = True
        mock_creds.token = "existing-token"
        mock_from_sa.return_value = mock_creds
        return mock_creds

    def _given_auth_hook(creds):
        with patch(
            "google_secops_siem_incidents.client_api.Credentials.from_service_account_info",
            return_value=creds,
        ):
            client = GoogleSecOpsApiClient(config=make_config())
        return client._auth_hook

    async def _when_before_hook_is_called(hook):
        request = MagicMock()
        request.headers = {}
        await hook.before(request)
        return request

    def _then_credentials_not_refreshed_but_header_set(creds, request):
        creds.refresh.assert_not_called()
        assert request.headers["Authorization"] == "Bearer existing-token"

    creds = _given_valid_credentials()
    hook = _given_auth_hook(creds)
    request = await _when_before_hook_is_called(hook)
    _then_credentials_not_refreshed_but_header_set(creds, request)


# ---------------------------------------------------------------------------
# Scenario: Initialization fails with invalid service account information
# ---------------------------------------------------------------------------
@patch("google_secops_siem_incidents.client_api.Credentials.from_service_account_info")
def test_initialization_fails_with_invalid_credentials(mock_from_sa):
    """Invalid service-account info causes initialization to raise."""

    def _given_invalid_config():
        mock_from_sa.side_effect = ValueError("Invalid service account info")
        return make_config()

    def _then_initialization_raises(config):
        with pytest.raises((ValueError, Exception)):
            GoogleSecOpsApiClient(config=config)

    config = _given_invalid_config()
    _then_initialization_raises(config)
