# -*- coding: utf-8 -*-
"""Tests for the connector settings: defaults, validators and helper config."""

import pytest
from connectors_sdk.settings.exceptions import ConfigValidationError
from src.xposedornot.settings import (
    SUPPORTED_SCOPE_ENTITY_TYPES,
    ConnectorSettings,
)


def _settings(monkeypatch, **overrides):
    env = {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "test-token",
        "CONNECTOR_LOG_LEVEL": "error",
    }
    env.update(overrides)
    for key in (
        "CONNECTOR_ID",
        "CONNECTOR_NAME",
        "CONNECTOR_SCOPE",
        "CONNECTOR_AUTO",
        "XPOSEDORNOT_API_KEY",
        "XPOSEDORNOT_API_BASE_URL",
        "XPOSEDORNOT_MAX_TLP",
        "XPOSEDORNOT_TLP_LEVEL",
        "XPOSEDORNOT_MAX_NOTE_BREACHES",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return ConnectorSettings()


def test_defaults_are_the_documented_ones(monkeypatch):
    settings = _settings(monkeypatch)
    assert settings.connector.id == "c6b0f5f2-c47e-4d49-92a9-10371b40f5d8"
    assert settings.connector.name == "XposedOrNot"
    assert settings.connector.scope == ["Email-Addr"]
    assert settings.connector.auto is False
    assert settings.xposedornot.api_key is None
    assert str(settings.xposedornot.api_base_url).startswith(
        "https://api.xposedornot.com"
    )
    assert settings.xposedornot.max_tlp == "TLP:AMBER"
    assert settings.xposedornot.tlp_level == "amber"
    assert settings.xposedornot.max_note_breaches == 50


def test_to_helper_config_carries_the_connector_block(monkeypatch):
    config = _settings(monkeypatch).to_helper_config()
    assert isinstance(config, dict)
    assert config["connector"]["type"] == "INTERNAL_ENRICHMENT"
    assert config["connector"]["scope"] == "Email-Addr"


def test_missing_mandatory_variable_is_rejected(monkeypatch):
    """A mandatory variable that is absent must fail at startup.

    An empty value is accepted by the SDK's own OpenCTI block, which this
    connector does not override; only absence is guaranteed to be caught.
    """
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    with pytest.raises(ConfigValidationError):
        ConnectorSettings()


def test_plain_http_base_url_is_rejected(monkeypatch):
    with pytest.raises(ConfigValidationError) as raised:
        _settings(monkeypatch, XPOSEDORNOT_API_BASE_URL="http://api.xposedornot.com")
    assert "must use https" in str(raised.value.__cause__)


def test_unsupported_scope_is_rejected(monkeypatch):
    with pytest.raises(ConfigValidationError) as raised:
        _settings(monkeypatch, CONNECTOR_SCOPE="Email-Addr,Domain-Name")
    assert "Domain-Name" in str(raised.value.__cause__)
    assert "Email-Addr" in SUPPORTED_SCOPE_ENTITY_TYPES


def test_blank_connector_id_is_rejected(monkeypatch):
    """Compose expands an unset ${CONNECTOR_ID} to an empty string, which would
    otherwise override the default and register the connector with no id."""
    with pytest.raises(ConfigValidationError):
        _settings(monkeypatch, CONNECTOR_ID="")


def test_negative_note_cap_is_rejected(monkeypatch):
    with pytest.raises(ConfigValidationError):
        _settings(monkeypatch, XPOSEDORNOT_MAX_NOTE_BREACHES="-1")


def test_every_sdk_tlp_level_is_accepted(monkeypatch):
    from connectors_sdk.models.enums import TLPLevel

    for level in [entry.value for entry in TLPLevel]:
        settings = _settings(monkeypatch, XPOSEDORNOT_TLP_LEVEL=level)
        assert settings.xposedornot.tlp_level == level
