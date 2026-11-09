from typing import Any
from uuid import UUID

import pytest
from connector import ConnectorSettings
from connectors_sdk import ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "DomainTools IrisQL",
                    "scope": "stix2",
                    "log_level": "error",
                    "duration_period": "PT1H",
                },
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-investigate/",
                    "api_key": "test-api-key",
                    "iris_ql": '# IrisQL-1.0\ndomain contains "sso"',
                    "store_iris_data": True,
                    "tlp_level": "amber+strict",
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-investigate/",
                    "api_key": "test-api-key",
                    "iris_ql": '# IrisQL-1.0\ndomain contains "sso"',
                },
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()

    assert settings.domaintools.api_key.get_secret_value() == "test-api-key"
    assert settings.domaintools.iris_ql == '# IrisQL-1.0\ndomain contains "sso"'


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {},
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-investigate/",
                    "api_key": "test-api-key",
                    "iris_ql": "query",
                },
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": 123456},
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-investigate/",
                    "api_key": "test-api-key",
                    "iris_ql": "query",
                },
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-investigate/",
                    "iris_ql": "query",
                },
            },
            id="missing_domaintools_api_key",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {},
                "domaintools": {
                    "api_base_url": "https://api.domaintools.com/v1/iris-investigate/",
                    "api_key": "test-api-key",
                    "iris_ql": "query",
                    "tlp_level": "purple",
                },
            },
            id="invalid_tlp_level",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()

    assert "Error validating configuration" in str(err.value)


def test_settings_should_default_connector_id():
    """The connector id MUST fall back on its unique default UUID v4."""

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {},
                    "domaintools": {
                        "api_base_url": "https://api.domaintools.com/v1/iris-investigate/",
                        "api_key": "test-api-key",
                        "iris_ql": "query",
                    },
                }
            )

    settings = FakeConnectorSettings()

    assert settings.connector.id == "b36f3005-427d-443b-bb34-e8534d0cf8a0"
    assert UUID(settings.connector.id).version == 4
    assert settings.connector.scope == ["stix2"]
