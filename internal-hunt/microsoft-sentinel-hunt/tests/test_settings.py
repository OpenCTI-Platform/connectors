import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connectors_sdk import ConfigValidationError
from microsoft_sentinel_hunt import ConnectorSettings


def _settings_dict(overrides: dict[str, Any]) -> dict[str, Any]:
    values = copy.deepcopy(VALID_SETTINGS)
    for namespace, items in overrides.items():
        values.setdefault(namespace, {}).update(items)
    return values


def _fake_settings_class(settings_dict: dict[str, Any]) -> type[ConnectorSettings]:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _: Any, handler: Any) -> Any:
            return handler(settings_dict)

    return FakeConnectorSettings


def test_settings_should_accept_valid_input():
    # Given valid app registration settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict({}))

    # When they are loaded
    settings = FakeConnectorSettings()

    # Then the Microsoft Sentinel hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "microsoft-sentinel"
    assert settings.connector.security_platform_name == "Microsoft Sentinel"
    config = settings.microsoft_sentinel_hunt
    assert config.auth_type == "app_registration"
    assert config.sigma_pipeline == "sentinel_asim"
    assert str(config.api_url) == "https://api.loganalytics.io/"
    assert config.authority_host == "login.microsoftonline.com"
    assert config.additional_workspaces == []


def test_settings_should_accept_azure_credential_without_secrets():
    # Given the DefaultAzureCredential method and other workspaces
    FakeConnectorSettings = _fake_settings_class(
        _settings_dict(
            {
                "microsoft_sentinel_hunt": {
                    "auth_type": "azure_credential",
                    "tenant_id": None,
                    "client_id": None,
                    "client_secret": None,
                    "additional_workspaces": "ws-2,ws-3",
                }
            }
        )
    )

    # When/Then the settings are valid
    settings = FakeConnectorSettings()
    assert settings.microsoft_sentinel_hunt.additional_workspaces == ["ws-2", "ws-3"]


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(
            {"microsoft_sentinel_hunt": {"workspace_id": None}}, id="no_workspace"
        ),
        pytest.param(
            {"microsoft_sentinel_hunt": {"client_secret": None}}, id="no_secret"
        ),
        pytest.param({"microsoft_sentinel_hunt": {"tenant_id": "  "}}, id="blank"),
        pytest.param(
            {"microsoft_sentinel_hunt": {"auth_type": "certificate"}}, id="auth_type"
        ),
        pytest.param({"microsoft_sentinel_hunt": {"api_url": "nope"}}, id="bad_url"),
        pytest.param(
            {"connector": {"scope": "microsoft-sentinel,splunk"}}, id="two_scopes"
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given invalid settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict(overrides))

    # When/Then they are rejected
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
