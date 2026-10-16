import pytest
from conftest import settings_class
from connectors_sdk import ConfigValidationError


def test_settings_should_accept_valid_input():
    # Given/When valid Censys settings are loaded
    FakeConnectorSettings = settings_class()
    settings = FakeConnectorSettings()

    # Then the Censys hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "censys"
    assert settings.connector.name == "Censys Platform Hunt"
    assert settings.connector.security_platform_name is None
    assert settings.connector.max_concurrent_runs == 1
    config = settings.censys_hunt
    assert config.token.get_secret_value() == "censys-token"
    assert config.organization_id == "org-1"
    assert str(config.api_url) == "https://api.platform.censys.io/"
    assert config.create_certificates is True


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"censys_hunt": {"token": " "}}, id="blank_token"),
        pytest.param({"censys_hunt": {"token": None}}, id="no_token"),
        pytest.param({"censys_hunt": {"api_url": "not a url"}}, id="bad_url"),
        pytest.param(
            {"connector": {"security_platform_name": "Censys"}},
            id="security_platform",
        ),
        pytest.param({"connector": {"scope": "splunk"}}, id="telemetry_platform"),
        pytest.param({"connector": {"max_concurrent_runs": 0}}, id="no_run"),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given/When/Then invalid settings are rejected
    FakeConnectorSettings = settings_class(overrides)
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
