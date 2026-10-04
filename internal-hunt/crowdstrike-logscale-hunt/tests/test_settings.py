import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connectors_sdk import ConfigValidationError
from crowdstrike_logscale_hunt import ConnectorSettings


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
    # Given valid Falcon settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict({}))

    # When they are loaded
    settings = FakeConnectorSettings()

    # Then the CrowdStrike LogScale hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "crowdstrike-logscale"
    assert settings.connector.security_platform_name == "CrowdStrike Falcon"
    config = settings.crowdstrike_logscale_hunt
    assert config.deployment == "falcon"
    assert str(config.base_url) == "https://api.crowdstrike.com/"
    assert config.repository == "search-all"
    assert config.sigma_pipeline == "crowdstrike_falcon"


def test_settings_should_accept_a_logscale_cluster():
    # Given LogScale cluster settings without Falcon credentials
    FakeConnectorSettings = _fake_settings_class(
        _settings_dict(
            {
                "crowdstrike_logscale_hunt": {
                    "deployment": "logscale",
                    "client_id": None,
                    "client_secret": None,
                    "logscale_url": "https://cloud.us.humio.com",
                    "logscale_token": "token-1",
                    "repository": "windows",
                }
            }
        )
    )

    # When/Then the settings are valid
    config = FakeConnectorSettings().crowdstrike_logscale_hunt
    assert config.deployment == "logscale"
    assert config.repository == "windows"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(
            {"crowdstrike_logscale_hunt": {"client_secret": " "}}, id="no_secret"
        ),
        pytest.param(
            {"crowdstrike_logscale_hunt": {"client_id": None}}, id="no_client_id"
        ),
        pytest.param(
            {
                "crowdstrike_logscale_hunt": {
                    "deployment": "logscale",
                    "logscale_token": "t",
                }
            },
            id="no_logscale_url",
        ),
        pytest.param(
            {
                "crowdstrike_logscale_hunt": {
                    "deployment": "logscale",
                    "logscale_url": "https://logscale.example.com",
                }
            },
            id="no_logscale_token",
        ),
        pytest.param(
            {"crowdstrike_logscale_hunt": {"deployment": "humio"}}, id="deployment"
        ),
        pytest.param(
            {"crowdstrike_logscale_hunt": {"poll_interval": 0}}, id="poll_interval"
        ),
        pytest.param(
            {"connector": {"scope": "crowdstrike-logscale,splunk"}}, id="two_scopes"
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given invalid settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict(overrides))

    # When/Then they are rejected
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
