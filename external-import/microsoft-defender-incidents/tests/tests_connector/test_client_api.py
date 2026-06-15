from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from microsoft_defender_incidents_connector import ConnectorSettings
from microsoft_defender_incidents_connector.client_api import ConnectorClient
from requests.exceptions import HTTPError


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "microsoft_defender_incidents": {
                    "tenant_id": "test-tenant-id",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "api_base_url": "https://graph.microsoft.com/v1.0",
                    "incident_path": "/security/incidents",
                    "import_start_date": "2020-01-01T00:00:00Z",
                },
            }
        )


def test_set_oauth_token_sends_bearer_authorization_header():
    """
    `set_oauth_token` MUST:
        - request the token from the tenant-specific OAuth endpoint using the unwrapped client secret
        - store the access token as a `Bearer` Authorization header (Microsoft Graph rejects raw tokens with 401)
    """
    settings = StubConnectorSettings()
    client = ConnectorClient(helper=MagicMock(), config=settings)

    response = MagicMock()
    response.text = '{"access_token": "fake-access-token"}'

    with patch(
        "microsoft_defender_incidents_connector.client_api.requests.post",
        return_value=response,
    ) as mocked_post:
        client.set_oauth_token()

    mocked_post.assert_called_once()
    _, call_kwargs = mocked_post.call_args
    posted_data = call_kwargs["data"]
    assert posted_data["client_id"] == "test-client-id"
    # The secret must be unwrapped from `SecretStr` before being sent
    assert posted_data["client_secret"] == "test-client-secret"
    assert client.session.headers["Authorization"] == "Bearer fake-access-token"


def test_set_oauth_token_raises_on_http_error():
    """
    `set_oauth_token` MUST surface a non-2xx OAuth response as an error instead of
    failing later with a confusing `KeyError` on the missing `access_token`.
    """
    settings = StubConnectorSettings()
    client = ConnectorClient(helper=MagicMock(), config=settings)

    response = MagicMock()
    response.raise_for_status.side_effect = HTTPError("401 Client Error: Unauthorized")

    with patch(
        "microsoft_defender_incidents_connector.client_api.requests.post",
        return_value=response,
    ):
        with pytest.raises(ValueError):
            client.set_oauth_token()


def test_query_builder_normalizes_incident_path_without_leading_slash():
    """
    `query_builder` MUST build a well-formed URL even when `incident_path` is configured
    without a leading slash (no missing or duplicated `/` between base URL and path).
    """
    config = MagicMock()
    md_config = config.microsoft_defender_incidents
    md_config.api_base_url = "https://graph.microsoft.com/v1.0"
    md_config.incident_path = "security/incidents"
    client = ConnectorClient(helper=MagicMock(), config=config)

    request = client.query_builder("2020-01-01T00:00:00+00:00")

    assert request.url.startswith("https://graph.microsoft.com/v1.0/security/incidents")
