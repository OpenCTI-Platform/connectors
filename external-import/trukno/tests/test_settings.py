from datetime import timedelta

import pytest
from connectors_sdk.settings.exceptions import ConfigValidationError
from pydantic import HttpUrl, SecretStr
from trukno_connector import ConnectorSettings
from trukno_connector.settings import _minutes_to_duration


def test_settings_require_opencti_url(required_environment, monkeypatch):
    monkeypatch.delenv("OPENCTI_URL")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_settings_require_opencti_token(required_environment, monkeypatch):
    monkeypatch.delenv("OPENCTI_TOKEN")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_settings_require_connector_id(required_environment, monkeypatch):
    monkeypatch.delenv("CONNECTOR_ID")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_settings_require_trukno_api_key(required_environment, monkeypatch):
    monkeypatch.delenv("TRUKNO_API_KEY")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_settings_apply_trukno_defaults(required_environment):
    settings = ConnectorSettings()

    assert settings.opencti.url == HttpUrl("http://opencti:8080")
    assert settings.connector.name == "TruKno"
    assert settings.connector.scope == ["report", "attack-pattern", "malware"]
    assert settings.connector.type == "EXTERNAL_IMPORT"
    assert settings.connector.duration_period == timedelta(hours=1)
    assert settings.trukno.api_base_url == HttpUrl("https://api.trukno.com/v2")
    assert settings.trukno.initial_lookback == timedelta(days=30)


@pytest.mark.parametrize(
    "name",
    [
        "CONNECTOR_DURATION_PERIOD",
        "TRUKNO_API_BASE_URL",
        "TRUKNO_INITIAL_LOOKBACK",
    ],
)
def test_settings_reject_blank_typed_optional_environment_values(
    required_environment, monkeypatch, name
):
    monkeypatch.setenv(name, "")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_settings_parse_scope_from_comma_separated_environment(
    required_environment, monkeypatch
):
    monkeypatch.setenv("CONNECTOR_SCOPE", "report, attack-pattern, malware")

    settings = ConnectorSettings()

    assert settings.connector.scope == ["report", "attack-pattern", "malware"]


def test_settings_keep_trukno_api_key_secret(required_environment):
    settings = ConnectorSettings()

    assert isinstance(settings.trukno.api_key, SecretStr)
    assert settings.trukno.api_key.get_secret_value() == "trukno-secret"
    assert "trukno-secret" not in repr(settings.trukno.api_key)


def test_settings_serialize_helper_config_without_exposing_trukno_secret(
    required_environment,
):
    settings = ConnectorSettings()

    helper_config = settings.to_helper_config()

    assert helper_config["opencti"]["token"] == "opencti-token"
    assert helper_config["connector"]["scope"] == "report,attack-pattern,malware"
    assert helper_config["connector"]["duration_period"] == "PT1H"
    assert helper_config["trukno"]["api_key"] == "**********"
    assert helper_config["trukno"]["initial_lookback"] == "P30D"


def test_settings_migrate_deprecated_interval_to_duration(
    required_environment, monkeypatch
):
    monkeypatch.setenv("TRUKNO_INTERVAL_MINUTES", "15")

    with pytest.warns(UserWarning, match="interval_minutes"):
        settings = ConnectorSettings()

    assert settings.connector.duration_period == timedelta(minutes=15)


@pytest.mark.parametrize("interval_minutes", ["0", "-1"])
def test_settings_reject_non_positive_deprecated_interval(
    required_environment, monkeypatch, interval_minutes
):
    monkeypatch.setenv("TRUKNO_INTERVAL_MINUTES", interval_minutes)

    with pytest.warns(UserWarning, match="interval_minutes"):
        with pytest.raises(ConfigValidationError):
            ConnectorSettings()


@pytest.mark.parametrize("interval_minutes", ["0", "-1", "abc", "1.5", ""])
def test_settings_preserve_canonical_duration_over_invalid_deprecated_interval(
    required_environment, monkeypatch, interval_minutes
):
    monkeypatch.setenv("TRUKNO_INTERVAL_MINUTES", interval_minutes)
    monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT1H")

    with pytest.warns(UserWarning, match="interval_minutes"):
        settings = ConnectorSettings()

    assert settings.connector.duration_period == timedelta(hours=1)


def test_settings_preserve_canonical_duration_over_valid_deprecated_interval(
    required_environment, monkeypatch
):
    monkeypatch.setenv("TRUKNO_INTERVAL_MINUTES", "15")
    monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT1H")

    with pytest.warns(UserWarning, match="interval_minutes"):
        settings = ConnectorSettings()

    assert settings.connector.duration_period == timedelta(hours=1)


@pytest.mark.parametrize("duration_period", ["PT0S", "-PT1S"])
def test_settings_reject_non_positive_duration(
    required_environment, monkeypatch, duration_period
):
    monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", duration_period)

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


@pytest.mark.parametrize("initial_lookback", ["PT0S", "-PT1S"])
def test_settings_reject_non_positive_initial_lookback(
    required_environment, monkeypatch, initial_lookback
):
    monkeypatch.setenv("TRUKNO_INITIAL_LOOKBACK", initial_lookback)

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_settings_schema_rejects_non_positive_initial_lookback():
    schema = ConnectorSettings.model_json_schema()
    lookback_schema = schema["$defs"]["TruKnoConfig"]["properties"]["initial_lookback"]

    assert lookback_schema["default"] == "P30D"
    assert lookback_schema["format"] == "duration"
    assert lookback_schema["type"] == "string"
    assert "initial_lookback_days" not in schema["$defs"]["TruKnoConfig"]["properties"]


@pytest.mark.parametrize(
    "value", [True, False, 1.0, 1.5, "1.5", "", " ", "abc", "1_0", None, 0, -1]
)
def test_minutes_to_duration_rejects_non_integer_or_non_positive_values(value):
    with pytest.raises(ValueError, match="positive integer"):
        _minutes_to_duration(value)


@pytest.mark.parametrize("value", [15, "15", "+15", "015", " 15 "])
def test_minutes_to_duration_accepts_integer_values(value):
    assert _minutes_to_duration(value) == timedelta(minutes=15)
