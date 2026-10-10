import pytest
from connectors_sdk.settings.exceptions import ConfigValidationError
from src.xposedornot.settings import ConnectorSettings

OWN_VARS = (
    "CONNECTOR_ID",
    "CONNECTOR_NAME",
    "CONNECTOR_SCOPE",
    "CONNECTOR_AUTO",
    "XPOSEDORNOT_API_KEY",
    "XPOSEDORNOT_API_BASE_URL",
    "XPOSEDORNOT_MAX_TLP",
    "XPOSEDORNOT_TLP_LEVEL",
    "XPOSEDORNOT_MAX_NOTE_BREACHES",
    "XPOSEDORNOT_UPDATE_SCORE",
)


def settings_from_env(monkeypatch, **overrides):
    for key in OWN_VARS:
        monkeypatch.delenv(key, raising=False)
    env = {"OPENCTI_URL": "http://localhost:8080", "OPENCTI_TOKEN": "test-token"}
    for key, value in {**env, **overrides}.items():
        monkeypatch.setenv(key, value)
    return ConnectorSettings()


def test_defaults_are_the_documented_ones(monkeypatch):
    settings = settings_from_env(monkeypatch)
    assert settings.connector.id == "c6b0f5f2-c47e-4d49-92a9-10371b40f5d8"
    assert settings.connector.scope == ["Email-Addr"]
    assert settings.connector.auto is False
    assert settings.xposedornot.api_key is None
    assert str(settings.xposedornot.api_base_url).startswith(
        "https://api.xposedornot.com"
    )
    assert settings.xposedornot.max_tlp == "TLP:AMBER"
    assert settings.xposedornot.tlp_level == "amber"
    assert settings.xposedornot.max_note_breaches == 50
    assert settings.xposedornot.update_score is True
    assert settings.to_helper_config()["connector"]["type"] == "INTERNAL_ENRICHMENT"


def test_environment_overrides_are_read(monkeypatch):
    settings = settings_from_env(
        monkeypatch,
        XPOSEDORNOT_API_KEY="k",
        XPOSEDORNOT_UPDATE_SCORE="false",
        XPOSEDORNOT_MAX_NOTE_BREACHES="0",
        XPOSEDORNOT_TLP_LEVEL="red",
    )
    assert settings.xposedornot.api_key.get_secret_value() == "k"
    assert settings.xposedornot.update_score is False
    assert settings.xposedornot.max_note_breaches == 0
    assert settings.xposedornot.tlp_level == "red"


@pytest.mark.parametrize(
    "variable, value",
    [
        ("CONNECTOR_SCOPE", "Email-Addr,IPv4-Addr"),
        ("XPOSEDORNOT_API_BASE_URL", "http://api.xposedornot.com"),
        ("XPOSEDORNOT_MAX_NOTE_BREACHES", "-1"),
        ("XPOSEDORNOT_TLP_LEVEL", "purple"),
        ("XPOSEDORNOT_MAX_TLP", "TLP:PINK"),
        ("CONNECTOR_ID", ""),
    ],
)
def test_invalid_values_are_rejected_at_startup(monkeypatch, variable, value):
    with pytest.raises(ConfigValidationError):
        settings_from_env(monkeypatch, **{variable: value})
