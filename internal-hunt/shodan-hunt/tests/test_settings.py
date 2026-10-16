import pytest
from conftest import settings_class
from connectors_sdk import ConfigValidationError


def test_settings_should_accept_valid_input():
    # Given/When valid Shodan settings are loaded
    FakeConnectorSettings = settings_class()
    settings = FakeConnectorSettings()

    # Then the Shodan hunt defaults apply
    assert settings.connector.platform == "shodan"
    assert settings.connector.name == "Shodan Hunt"
    assert settings.connector.security_platform_name is None
    assert settings.connector.max_concurrent_runs == 1
    config = settings.shodan_hunt
    assert config.api_key.get_secret_value() == "shodan-secret-key"
    assert str(config.api_url) == "https://api.shodan.io/"
    assert config.create_certificates is True


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"shodan_hunt": {"api_key": " "}}, id="blank_key"),
        pytest.param({"shodan_hunt": {"api_key": None}}, id="no_key"),
        pytest.param({"shodan_hunt": {"api_url": "not a url"}}, id="bad_url"),
        pytest.param(
            {"connector": {"security_platform_name": "Shodan"}},
            id="security_platform",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given/When/Then invalid settings are rejected
    FakeConnectorSettings = settings_class(overrides)
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
