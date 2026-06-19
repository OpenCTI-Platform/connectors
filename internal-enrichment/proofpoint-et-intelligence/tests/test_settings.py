from typing import Any

import pytest
from connector.settings import ConnectorSettings
from connectors_sdk import ConfigValidationError


class FakeConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(cls._test_config)


@pytest.mark.parametrize(
    "config_id,config_dict",
    [
        (
            "full_valid_settings_dict",
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token-for-testing",
                },
                "connector": {
                    "id": "f2de8084-47ab-4ff2-ae63-e5a7c6e5c720",
                    "name": "ProofPoint ET Intelligence",
                    "scope": "IPv4-Addr,Domain-Name,StixFile",
                    "auto": True,
                },
                "proofpoint_et_intelligence": {
                    "api_base_url": "https://api.emergingthreats.net/v1/",
                    "api_key": "my-secret-api-key",
                    "max_tlp": "TLP:AMBER+STRICT",
                    "import_last_seen_time_window": "P30D",
                },
            },
        ),
        (
            "minimal_valid_settings_dict",
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token-for-testing",
                },
                "connector": {},
                "proofpoint_et_intelligence": {
                    "api_key": "my-secret-api-key",
                },
            },
        ),
    ],
)
def test_settings_should_accept_valid_input(config_id, config_dict):
    FakeConnectorSettings._test_config = config_dict
    settings = FakeConnectorSettings()
    assert str(settings.opencti.url).rstrip("/") == config_dict["opencti"]["url"]
    assert (
        settings.proofpoint_et_intelligence.api_key.get_secret_value()
        == config_dict["proofpoint_et_intelligence"]["api_key"]
    )


@pytest.mark.parametrize(
    "config_id,config_dict",
    [
        (
            "empty_settings_dict",
            {},
        ),
        (
            "missing_opencti_token",
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "proofpoint_et_intelligence": {"api_key": "key"},
            },
        ),
        (
            "invalid_connector_id",
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {"id": 12345},
                "proofpoint_et_intelligence": {"api_key": "key"},
            },
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(config_id, config_dict):
    FakeConnectorSettings._test_config = config_dict
    with pytest.raises(ConfigValidationError, match="Error validating configuration"):
        FakeConnectorSettings()
