import pytest
from conftest import settings_class
from connectors_sdk import ConfigValidationError


def test_settings_should_accept_valid_input():
    # Given/When valid urlscan.io settings are loaded
    FakeConnectorSettings = settings_class()
    settings = FakeConnectorSettings()

    # Then the urlscan.io hunt defaults apply
    assert settings.connector.platform == "urlscan"
    assert settings.connector.name == "urlscan.io Hunt"
    assert settings.connector.security_platform_name is None
    assert settings.connector.max_concurrent_runs == 2
    config = settings.urlscan_hunt
    assert config.api_key.get_secret_value() == "us-key"
    assert str(config.api_url) == "https://urlscan.io/"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"urlscan_hunt": {"api_key": " "}}, id="blank_key"),
        pytest.param({"urlscan_hunt": {"api_key": None}}, id="no_key"),
        pytest.param({"urlscan_hunt": {"api_url": "not a url"}}, id="bad_url"),
        pytest.param(
            {"connector": {"security_platform_name": "urlscan.io"}},
            id="security_platform",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given/When/Then invalid settings are rejected
    FakeConnectorSettings = settings_class(overrides)
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
