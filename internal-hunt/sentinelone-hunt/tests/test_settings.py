import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connectors_sdk import ConfigValidationError
from sentinelone_hunt import ConnectorSettings


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
    # Given valid SentinelOne settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict({}))

    # When they are loaded
    settings = FakeConnectorSettings()

    # Then the SentinelOne hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "sentinelone"
    assert settings.connector.security_platform_name == "SentinelOne Singularity"
    assert settings.connector.security_platform_type == "EDR"
    assert settings.connector.max_concurrent_runs == 3
    config = settings.sentinelone_hunt
    assert str(config.api_url) == "https://tenant.sentinelone.net/"
    assert config.api_token.get_secret_value() == "s1-token"
    assert config.account_ids == []
    assert config.edr_only is True
    assert config.sigma_pipeline == "sentinelone_pq"
    assert config.poll_interval == 1.0


def test_settings_should_read_account_ids_from_a_comma_separated_string():
    # Given account IDs written as an environment variable would be
    FakeConnectorSettings = _fake_settings_class(
        _settings_dict({"sentinelone_hunt": {"account_ids": " 111, ,222 "}})
    )

    # When/Then they become a list without blanks
    assert FakeConnectorSettings().sentinelone_hunt.account_ids == ["111", "222"]


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"sentinelone_hunt": {"api_token": " "}}, id="blank_token"),
        pytest.param({"sentinelone_hunt": {"api_token": None}}, id="no_token"),
        pytest.param({"sentinelone_hunt": {"api_url": None}}, id="no_url"),
        pytest.param({"sentinelone_hunt": {"api_url": "not a url"}}, id="bad_url"),
        pytest.param({"sentinelone_hunt": {"poll_interval": 0}}, id="poll_zero"),
        pytest.param({"sentinelone_hunt": {"poll_interval": 30}}, id="poll_expiry"),
        pytest.param(
            {"connector": {"security_platform_type": "AV"}}, id="platform_type"
        ),
        pytest.param({"connector": {"scope": "sentinelone,splunk"}}, id="two_scopes"),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given invalid settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict(overrides))

    # When/Then they are rejected
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
