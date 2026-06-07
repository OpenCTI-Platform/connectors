from typing import Any
from unittest.mock import MagicMock, patch

from microsoft_defender_incidents_connector import ConnectorSettings
from microsoft_defender_incidents_connector.client_api import ConnectorClient


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
