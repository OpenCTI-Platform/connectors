from typing import Any

import pytest
from doppel.settings import ConnectorSettings, DoppelConfig
from pydantic import ValidationError


def test_connector_settings_accepts_valid_v1_configuration():
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {
                        "url": "http://localhost:8080",
                        "token": "test-token",
                    },
                    "connector": {"id": "connector-id"},
                    "doppel": {"api_key": "api-key"},
                }
            )

    settings = FakeConnectorSettings()

    assert settings.doppel.api_version == "v1"
    assert settings.doppel.api_key is not None
    assert settings.doppel.api_key.get_secret_value() == "api-key"


def test_v1_requires_api_key():
    with pytest.raises(ValidationError, match="api_key is required"):
        DoppelConfig()


def test_v1_accepts_static_credentials():
    config = DoppelConfig(
        api_key="api-key",
        user_api_key="user-api-key",
        organization_code="ACM",
    )

    assert config.api_version == "v1"
    assert config.api_key is not None
    assert config.api_key.get_secret_value() == "api-key"


def test_v2_requires_client_credentials():
    with pytest.raises(ValidationError, match="client_secret is required"):
        DoppelConfig(api_version="v2", client_id="client-id")


def test_v2_accepts_client_credentials_without_v1_keys():
    config = DoppelConfig(
        api_version="v2",
        client_id="client-id",
        client_secret="client-secret",
    )

    assert config.api_key is None
    assert config.client_secret is not None
    assert config.client_secret.get_secret_value() == "client-secret"
    assert config.token_audience == "doppel-external"


def test_v1_rejects_v2_credentials():
    with pytest.raises(ValidationError, match="V2 OAuth settings must be unset"):
        DoppelConfig(
            api_version="v1",
            api_key="api-key",
            client_id="client-id",
            client_secret="client-secret",
        )


def test_v2_rejects_v1_credentials():
    with pytest.raises(ValidationError, match="V1 API key settings must be unset"):
        DoppelConfig(
            api_version="v2",
            api_key="api-key",
            client_id="client-id",
            client_secret="client-secret",
        )
