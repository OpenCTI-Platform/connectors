from unittest.mock import MagicMock

import pytest
import requests
from accenture_connector.client_api import ConnectorClient
from connectors_sdk import (
    ProviderApiAuthenticationError,
    ProviderApiAuthorizationError,
    ProviderApiConnectionError,
    ProviderApiInvalidResponseError,
    ProviderApiNotFoundError,
    ProviderApiRateLimitError,
    ProviderApiServerError,
    ProviderApiTimeoutError,
    ProviderApiUnknownError,
)


@pytest.fixture
def client(monkeypatch) -> ConnectorClient:
    """A client whose authentication succeeds without calling Cognito."""
    monkeypatch.setattr("accenture_connector.client_api.Cognito", MagicMock())
    return ConnectorClient(helper=MagicMock(), config=MagicMock())


def _http_error(status_code: int) -> requests.exceptions.HTTPError:
    response = requests.Response()
    response.status_code = status_code
    return requests.exceptions.HTTPError(f"{status_code} error", response=response)


def test_refresh_token_raises_authentication_error_when_cognito_fails(monkeypatch):
    cognito = MagicMock()
    cognito.return_value.authenticate.side_effect = RuntimeError("bad credentials")
    monkeypatch.setattr("accenture_connector.client_api.Cognito", cognito)
    client = ConnectorClient(helper=MagicMock(), config=MagicMock())

    with pytest.raises(ProviderApiAuthenticationError) as exc_info:
        client._refresh_and_set_token()

    assert isinstance(exc_info.value.__cause__, RuntimeError)


def test_get_reports_keeps_authentication_error(monkeypatch):
    """The authentication error is not rewrapped as another API error."""
    cognito = MagicMock()
    cognito.return_value.authenticate.side_effect = RuntimeError("bad credentials")
    monkeypatch.setattr("accenture_connector.client_api.Cognito", cognito)
    client = ConnectorClient(helper=MagicMock(), config=MagicMock())

    with pytest.raises(ProviderApiAuthenticationError):
        client.get_reports("2026-01-01T00:00:00Z", "2026-01-01T00:30:00Z")


def test_get_reports_returns_the_json_response(client):
    response = MagicMock()
    response.json.return_value = {"objects": []}
    client.session = MagicMock()
    client.session.get.return_value = response

    reports = client.get_reports("2026-01-01T00:00:00Z", "2026-01-01T00:30:00Z")

    assert reports == {"objects": []}


@pytest.mark.parametrize(
    ("raised", "expected_error"),
    [
        (_http_error(401), ProviderApiAuthenticationError),
        (_http_error(403), ProviderApiAuthorizationError),
        (_http_error(404), ProviderApiNotFoundError),
        (_http_error(429), ProviderApiRateLimitError),
        (_http_error(500), ProviderApiServerError),
        (_http_error(503), ProviderApiServerError),
        (_http_error(400), ProviderApiUnknownError),
        (requests.exceptions.ReadTimeout("timeout"), ProviderApiTimeoutError),
        # Both a ConnectionError and a Timeout: reported as a timeout
        (requests.exceptions.ConnectTimeout("timeout"), ProviderApiTimeoutError),
        (requests.exceptions.ConnectionError("refused"), ProviderApiConnectionError),
        (
            requests.exceptions.JSONDecodeError("Expecting value", "", 0),
            ProviderApiInvalidResponseError,
        ),
        (requests.exceptions.RequestException("other"), ProviderApiUnknownError),
    ],
)
def test_get_reports_raises_the_matching_provider_error(client, raised, expected_error):
    client.session = MagicMock()
    client.session.get.side_effect = raised

    with pytest.raises(expected_error) as exc_info:
        client.get_reports("2026-01-01T00:00:00Z", "2026-01-01T00:30:00Z")

    assert type(exc_info.value) is expected_error
    assert exc_info.value.__cause__ is raised
