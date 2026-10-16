import pytest
from conftest import settings_class
from connectors_sdk import ConfigValidationError


def test_settings_should_accept_valid_input():
    # Given/When valid Silent Push settings are loaded
    FakeConnectorSettings = settings_class()
    settings = FakeConnectorSettings()

    # Then the Silent Push hunt defaults apply
    assert settings.connector.platform == "silentpush"
    assert settings.connector.name == "Silent Push Hunt"
    assert settings.connector.security_platform_name is None
    assert settings.connector.max_concurrent_runs == 2
    config = settings.silentpush_hunt
    assert config.api_key.get_secret_value() == "sp-key"
    assert str(config.api_url) == "https://api.silentpush.com/"
    assert config.create_certificates is True


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"silentpush_hunt": {"api_key": " "}}, id="blank_key"),
        pytest.param({"silentpush_hunt": {"api_key": None}}, id="no_key"),
        pytest.param({"silentpush_hunt": {"api_url": "not a url"}}, id="bad_url"),
        pytest.param(
            {"connector": {"security_platform_name": "Silent Push"}},
            id="security_platform",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given/When/Then invalid settings are rejected
    FakeConnectorSettings = settings_class(overrides)
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
