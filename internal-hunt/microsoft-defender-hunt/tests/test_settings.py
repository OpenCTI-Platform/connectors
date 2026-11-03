import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connectors_sdk import ConfigValidationError
from microsoft_defender_hunt import ConnectorSettings


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

    # Then the Microsoft Defender XDR hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "microsoft-defender"
    assert settings.connector.security_platform_name == "Microsoft Defender XDR"
    assert settings.connector.security_platform_type == "XDR"
    config = settings.microsoft_defender_hunt
    assert config.sigma_pipeline == "microsoft_xdr"
    assert str(config.login_url) == "https://login.microsoftonline.com/"
    assert str(config.graph_url) == "https://graph.microsoft.com/"
    assert config.client_secret.get_secret_value() == "secret-1"


def test_settings_should_accept_a_national_cloud():
    # Given the URLs of Microsoft Graph for US Government L4, with blanks around the IDs
    FakeConnectorSettings = _fake_settings_class(
        _settings_dict(
            {
                "microsoft_defender_hunt": {
                    "tenant_id": " tenant-1 ",
                    "login_url": "https://login.microsoftonline.us",
                    "graph_url": "https://graph.microsoft.us",
                }
            }
        )
    )

    # When/Then the settings are valid, the IDs trimmed
    config = FakeConnectorSettings().microsoft_defender_hunt
    assert config.tenant_id == "tenant-1"
    assert str(config.graph_url) == "https://graph.microsoft.us/"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"microsoft_defender_hunt": {"tenant_id": None}}, id="no_tenant"),
        pytest.param(
            {"microsoft_defender_hunt": {"client_secret": None}}, id="no_secret"
        ),
        pytest.param({"microsoft_defender_hunt": {"client_id": "  "}}, id="blank_id"),
        pytest.param(
            {"microsoft_defender_hunt": {"client_secret": " "}}, id="blank_secret"
        ),
        pytest.param({"microsoft_defender_hunt": {"graph_url": "nope"}}, id="bad_url"),
        pytest.param(
            {"connector": {"scope": "microsoft-defender,splunk"}}, id="two_scopes"
        ),
        pytest.param(
            {"connector": {"security_platform_type": "CASB"}}, id="platform_type"
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given invalid settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict(overrides))

    # When/Then they are rejected
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
