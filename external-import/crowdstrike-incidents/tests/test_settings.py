"""Tests for the CrowdStrike Incidents connector settings."""

from datetime import timedelta

import pytest
from connectors_sdk import ConfigValidationError
from connectors_sdk.models.enums import TLPLevel
from crowdstrike_incidents.settings import (
    ConnectorSettings,
    CrowdstrikeIncidentsConfig,
    Severity,
)


def test_defaults(mock_env):
    settings = ConnectorSettings()

    assert settings.connector.name == "CrowdStrike Incidents"
    assert settings.connector.scope == ["crowdstrike-incidents"]
    assert settings.connector.duration_period == timedelta(minutes=5)

    config = settings.crowdstrike_incidents
    assert str(config.api_base_url) == "https://api.crowdstrike.com/"
    assert config.client_id == "synthetic-client-id"
    assert config.client_secret.get_secret_value() == "synthetic-secret"
    assert config.import_start_date == timedelta(days=7)
    assert config.products == ["ngsiem"]
    assert config.severity_min is None
    assert config.include_hidden is False
    assert config.tlp_level == TLPLevel.AMBER_STRICT


def test_secret_is_not_rendered(mock_env):
    settings = ConnectorSettings()

    assert "synthetic-secret" not in repr(settings.crowdstrike_incidents)


def test_overrides(mock_env, monkeypatch):
    monkeypatch.setenv(
        "CROWDSTRIKE_INCIDENTS_API_BASE_URL", "https://api.us-2.crowdstrike.com"
    )
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_IMPORT_START_DATE", "P30D")
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_SEVERITY_MIN", "high")
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_INCLUDE_HIDDEN", "true")
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_TLP_LEVEL", "red")
    monkeypatch.setenv("CONNECTOR_DURATION_PERIOD", "PT15M")

    settings = ConnectorSettings()
    config = settings.crowdstrike_incidents

    assert str(config.api_base_url) == "https://api.us-2.crowdstrike.com/"
    assert config.import_start_date == timedelta(days=30)
    assert config.severity_min == Severity.HIGH
    assert config.include_hidden is True
    assert config.tlp_level == TLPLevel.RED
    assert settings.connector.duration_period == timedelta(minutes=15)


@pytest.mark.parametrize("missing", ["CLIENT_ID", "CLIENT_SECRET"])
def test_credentials_are_required(mock_env, monkeypatch, missing):
    monkeypatch.delenv(f"CROWDSTRIKE_INCIDENTS_{missing}")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_products_are_normalised(mock_env, monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_PRODUCTS", " NGSIEM ,ngsiem")

    assert ConnectorSettings().crowdstrike_incidents.products == ["ngsiem"]


@pytest.mark.parametrize("products", ["epp", "ngsiem,epp", "", " , "])
def test_unsupported_products_are_rejected(mock_env, monkeypatch, products):
    """Regression (review): an unsupported value must be refused by the schema
    (and the XTM Composer form), not accepted then fail at startup."""
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_PRODUCTS", products)

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_products_schema_only_offers_supported_values():
    schema = CrowdstrikeIncidentsConfig.model_json_schema()
    items = schema["properties"]["products"]["items"]
    if "$ref" in items:
        items = schema["$defs"][items["$ref"].rsplit("/", 1)[-1]]

    assert items["enum"] == ["ngsiem"]


def test_invalid_severity_is_rejected(mock_env, monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_SEVERITY_MIN", "urgent")

    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


@pytest.mark.parametrize(
    "severity_name, threshold, expected",
    [
        ("Informational", Severity.LOW, False),
        ("Low", Severity.LOW, True),
        ("High", Severity.MEDIUM, True),
        ("Medium", Severity.HIGH, False),
        ("Critical", Severity.CRITICAL, True),
    ],
)
def test_severity_ordering(severity_name, threshold, expected):
    assert (Severity(severity_name.lower()) >= threshold) is expected


def test_enrichment_is_disabled_by_default(mock_env):
    assert ConnectorSettings().crowdstrike_incidents.enrich_from_events is False


def test_enrichment_can_be_enabled(mock_env, monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_INCIDENTS_ENRICH_FROM_EVENTS", "true")

    assert ConnectorSettings().crowdstrike_incidents.enrich_from_events is True
