import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connectors_sdk import ConfigValidationError
from splunk_hunt import ConnectorSettings


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
    # Given valid settings with a token
    FakeConnectorSettings = _fake_settings_class(_settings_dict({}))

    # When they are loaded
    settings = FakeConnectorSettings()

    # Then the Splunk hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "splunk"
    assert settings.connector.security_platform_name == "Splunk"
    assert settings.splunk_hunt.sigma_pipeline == "splunk_windows"
    assert settings.splunk_hunt.output_format == "default"
    assert settings.splunk_hunt.app == "search"


def test_settings_should_accept_basic_authentication():
    # Given credentials instead of a token
    FakeConnectorSettings = _fake_settings_class(
        _settings_dict(
            {"splunk_hunt": {"token": None, "username": "hunter", "password": "pw"}}
        )
    )

    # When/Then the settings are valid
    settings = FakeConnectorSettings()
    assert settings.splunk_hunt.username == "hunter"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"splunk_hunt": {"token": None}}, id="no_credentials"),
        pytest.param({"splunk_hunt": {"token": "  "}}, id="blank_token"),
        pytest.param(
            {"splunk_hunt": {"token": None, "username": "hunter"}},
            id="username_without_password",
        ),
        pytest.param({"splunk_hunt": {"url": "not a url"}}, id="invalid_url"),
        pytest.param(
            {"splunk_hunt": {"output_format": "savedsearches"}}, id="bad_format"
        ),
        pytest.param({"splunk_hunt": {"poll_interval": 0}}, id="null_poll"),
        pytest.param({"connector": {"scope": "opensearch,splunk"}}, id="two_scopes"),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given invalid settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict(overrides))

    # When/Then they are rejected
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
