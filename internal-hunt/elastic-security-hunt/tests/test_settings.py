import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connectors_sdk import ConfigValidationError
from elastic_security_hunt import ConnectorSettings


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
    # Given valid API key settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict({}))

    # When they are loaded
    settings = FakeConnectorSettings()

    # Then the Elastic Security hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "elastic-security"
    assert settings.connector.security_platform_name == "Elastic Security"
    config = settings.elastic_security_hunt
    assert config.query_language == "esql"
    assert config.sigma_pipeline == "ecs_windows"
    assert config.indices[0] == "logs-*"
    assert config.timestamp_field == "@timestamp"
    assert config.verify_ssl is True


def test_settings_should_accept_basic_authentication():
    # Given user name and password settings with custom indices
    FakeConnectorSettings = _fake_settings_class(
        _settings_dict(
            {
                "elastic_security_hunt": {
                    "api_key": None,
                    "username": "hunter",
                    "password": "secret",
                    "indices": "logs-endpoint.*,remote:logs-*",
                    "query_language": "eql",
                }
            }
        )
    )

    # When/Then the settings are valid
    config = FakeConnectorSettings().elastic_security_hunt
    assert config.indices == ["logs-endpoint.*", "remote:logs-*"]
    assert config.query_language == "eql"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"elastic_security_hunt": {"url": None}}, id="no_url"),
        pytest.param({"elastic_security_hunt": {"api_key": "  "}}, id="no_creds"),
        pytest.param(
            {"elastic_security_hunt": {"api_key": None, "username": "u"}},
            id="no_password",
        ),
        pytest.param(
            {"elastic_security_hunt": {"query_language": "kql"}}, id="language"
        ),
        pytest.param({"elastic_security_hunt": {"indices": ""}}, id="no_indices"),
        pytest.param(
            {"connector": {"scope": "elastic-security,splunk"}}, id="two_scopes"
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given invalid settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict(overrides))

    # When/Then they are rejected
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
