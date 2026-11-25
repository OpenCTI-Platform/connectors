from typing import Any
from uuid import UUID

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
from settings import ConnectorSettings

CONNECTOR_ID_DEFAULT = "80a2d7fa-6527-45d6-b1e6-bc3ef51e6f03"

MINIMAL_VALID_SETTINGS_DICT = {
    "opencti": {
        "url": "http://localhost:8080",
        "token": "test-token",
    },
    "connector": {},
    "rst_whois_api": {
        "api_key": "test-api-key",
    },
}


def _fake_settings(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings


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
                    "name": "RST WHOIS API",
                    "scope": "Domain-Name,Url,indicator",
                    "log_level": "info",
                    "auto": True,
                    "max_tlp": "TLP:RED",
                },
                "rst_whois_api": {
                    "api_key": "test-api-key",
                    "base_url": "https://api.example.com/v1",
                    "timeout": 30,
                    "whois_output_object": "description",
                    "update_output_action": "append",
                    "output_format": "extended",
                    "output_include_raw": True,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(MINIMAL_VALID_SETTINGS_DICT, id="minimal_valid_settings_dict"),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "rst-whois-api": {
                    "api_key": "test-api-key",
                },
            },
            id="legacy_config_yml_section_name",
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
    settings = _fake_settings(settings_dict)()

    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.rst_whois_api, BaseConfigModel) is True
    assert settings.rst_whois_api.api_key.get_secret_value() == "test-api-key"


def test_settings_should_apply_defaults():
    """
    Test that the minimal valid input yields the documented defaults.
    """
    settings = _fake_settings(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.name == "RST WHOIS API"
    assert settings.connector.scope == ["Domain-Name", "Url", "indicator"]
    assert settings.connector.type == "INTERNAL_ENRICHMENT"
    assert settings.connector.auto is False
    assert settings.connector.log_level == "error"
    assert settings.connector.max_tlp == TLPLevel.AMBER_STRICT
    assert settings.rst_whois_api.base_url == "https://api.rstcloud.net/v1"
    assert settings.rst_whois_api.timeout == 10
    assert settings.rst_whois_api.whois_output_object == "note"
    assert settings.rst_whois_api.update_output_action == "overwrite"
    assert settings.rst_whois_api.output_format == "standard"
    assert settings.rst_whois_api.output_include_raw is False


def test_settings_should_default_connector_id():
    """
    Test that the connector id defaults to the UUIDv4 declared in `settings.py`,
    so that the connector can be deployed from the catalog without manual input.
    """
    settings = _fake_settings(MINIMAL_VALID_SETTINGS_DICT)()

    assert settings.connector.id == CONNECTOR_ID_DEFAULT
    assert UUID(settings.connector.id).version == 4


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param({}, id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                },
                "connector": {},
                "rst_whois_api": {
                    "api_key": "test-api-key",
                },
            },
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {"id": 123456},
                "rst_whois_api": {
                    "api_key": "test-api-key",
                },
            },
            id="invalid_connector_id",
        ),
        pytest.param(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "rst_whois_api": {},
            },
            id="missing_rst_whois_api_api_key",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """
    FakeConnectorSettings = _fake_settings(settings_dict)

    with pytest.raises(ConfigValidationError) as err:
        FakeConnectorSettings()
    assert "Error validating configuration" in str(err)


def test_settings_should_migrate_deprecated_max_tlp_to_connector_max_tlp():
    """
    Test that the deprecated `rst_whois_api.max_tlp` (`RST_WHOIS_API_MAX_TLP`)
    is migrated to `connector.max_tlp` (`CONNECTOR_MAX_TLP`).
    """
    FakeConnectorSettings = _fake_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {},
            "rst_whois_api": {"api_key": "test-api-key", "max_tlp": "TLP:GREEN"},
        }
    )

    with pytest.warns(UserWarning, match="rst_whois_api.max_tlp"):
        settings = FakeConnectorSettings()

    assert settings.connector.max_tlp == TLPLevel.GREEN


def test_settings_should_prefer_connector_max_tlp_over_deprecated_max_tlp():
    """
    Test that `connector.max_tlp` wins when both it and the deprecated
    `rst_whois_api.max_tlp` are set.
    """
    FakeConnectorSettings = _fake_settings(
        {
            "opencti": {"url": "http://localhost:8080", "token": "test-token"},
            "connector": {"max_tlp": "TLP:RED"},
            "rst_whois_api": {"api_key": "test-api-key", "max_tlp": "TLP:GREEN"},
        }
    )

    with pytest.warns(UserWarning, match="Using only 'connector.max_tlp'"):
        settings = FakeConnectorSettings()

    assert settings.connector.max_tlp == TLPLevel.RED
