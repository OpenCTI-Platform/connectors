import copy
from typing import Any

import pytest
from conftest import VALID_SETTINGS
from connectors_sdk import ConfigValidationError
from google_secops_hunt import ConnectorSettings


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
    # Given valid service account settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict({}))

    # When they are loaded
    settings = FakeConnectorSettings()

    # Then the Google SecOps hunt defaults apply
    assert settings.connector.type == "INTERNAL_HUNT"
    assert settings.connector.platform == "google-secops"
    assert settings.connector.security_platform_name == "Google SecOps"
    config = settings.google_secops_hunt
    assert str(config.base_url) == "https://chronicle.googleapis.com/"
    assert config.query_language == "udm"
    assert config.sigma_pipeline == "secops_udm"
    assert config.token_uri == "https://oauth2.googleapis.com/token"
    assert config.client_cert_url == ""


def test_settings_should_restore_the_newlines_of_the_private_key():
    # Given a private key holding literal '\n' sequences (environment variable)
    FakeConnectorSettings = _fake_settings_class(_settings_dict({}))

    # When/Then the PEM key holds real newlines
    key = FakeConnectorSettings().google_secops_hunt.private_key.get_secret_value()
    assert key.splitlines()[1] == "key"
    assert "\\n" not in key


def test_settings_should_keep_a_multiline_private_key():
    # Given a private key already holding newlines (YAML)
    pem = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
    FakeConnectorSettings = _fake_settings_class(
        _settings_dict(
            {"google_secops_hunt": {"private_key": pem, "query_language": "yara-l"}}
        )
    )

    # When/Then it is kept as is
    config = FakeConnectorSettings().google_secops_hunt
    assert config.private_key.get_secret_value() == pem
    assert config.query_language == "yara-l"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"google_secops_hunt": {"project_id": None}}, id="no_project"),
        pytest.param({"google_secops_hunt": {"private_key": None}}, id="no_key"),
        pytest.param(
            {"google_secops_hunt": {"client_email": None}}, id="no_client_email"
        ),
        pytest.param({"google_secops_hunt": {"query_language": "spl"}}, id="language"),
        pytest.param({"google_secops_hunt": {"base_url": "not a url"}}, id="url"),
        pytest.param({"connector": {"scope": "google-secops,splunk"}}, id="two_scopes"),
    ],
)
def test_settings_should_raise_when_invalid_input(overrides):
    # Given invalid settings
    FakeConnectorSettings = _fake_settings_class(_settings_dict(overrides))

    # When/Then they are rejected
    with pytest.raises(ConfigValidationError):
        FakeConnectorSettings()
