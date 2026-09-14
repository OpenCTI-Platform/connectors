"""Tests for zetalytics_dns.settings."""

from typing import Any

import pytest
from connectors_sdk import BaseConfigModel, ConfigValidationError
from zetalytics_dns.settings import ConfigLoader


def _make_loader(config_dict: dict[str, Any]) -> ConfigLoader:
    """Return a ConfigLoader subclass that reads from config_dict instead of env/files."""

    class _Stub(ConfigLoader):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:  # type: ignore[override]
            return handler(config_dict)

    return _Stub()  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "config_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "tok"},
                "connector": {
                    "id": "00000000-0000-4000-8000-000000000101",
                    "scope": "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr",
                },
                "zetalytics": {"token": "zt"},
            },
            id="minimal_valid",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "tok"},
                "connector": {
                    "id": "00000000-0000-4000-8000-000000000101",
                    "name": "Zetalytics DNS - Analyst Enrichment",
                    "scope": "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr",
                    "log_level": "info",
                    "auto": False,
                },
                "zetalytics": {
                    "token": "zt",
                    "mode": "manual",
                    "max_results": 300,
                    "max_subdomains": 500,
                    "lookback_days": 365,
                    "include_live_dns": True,
                    "include_subdomains": True,
                    "include_d8s": True,
                    "include_historical_whois": False,
                    "include_ns_glue": True,
                    "confidence": 60,
                    "marking_definition": "TLP:AMBER",
                },
            },
            id="full_analyst_config",
        ),
    ],
)
def test_config_loader_accepts_valid_input(config_dict):
    config = _make_loader(config_dict)

    assert isinstance(config.opencti, BaseConfigModel)
    assert isinstance(config.connector, BaseConfigModel)
    assert isinstance(config.zetalytics, BaseConfigModel)


def test_config_loader_rejects_missing_zetalytics_token():
    """zetalytics.token is required; omitting it should raise a validation error."""
    config_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "tok"},
        "connector": {"id": "abc", "scope": "Domain-Name"},
        "zetalytics": {},  # token missing
    }
    with pytest.raises(Exception):
        _make_loader(config_dict)


def test_config_loader_rejects_fractional_lookback_days():
    """lookback_days is an int; a fractional day count (bad input) should be rejected outright."""
    config_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "tok"},
        "connector": {"id": "abc", "scope": "Domain-Name"},
        "zetalytics": {"token": "zt", "lookback_days": 912.5},
    }
    with pytest.raises(Exception):
        _make_loader(config_dict)


def test_config_defaults_applied():
    """Verify sensible defaults are applied when optional fields are omitted."""
    config = _make_loader(
        {
            "opencti": {"url": "http://localhost:8080", "token": "tok"},
            "connector": {"id": "abc", "scope": "Domain-Name"},
            "zetalytics": {"token": "zt"},
        }
    )

    assert config.zetalytics.mode == "manual"
    assert config.zetalytics.max_results == 300
    assert config.zetalytics.lookback_days == 365
    assert config.zetalytics.include_live_dns is True
    assert config.zetalytics.include_historical_whois is False
    assert config.zetalytics.confidence == 60


def test_light_mode_config():
    """Verify a light-mode deployment config loads correctly."""
    config = _make_loader(
        {
            "opencti": {"url": "http://localhost:8080", "token": "tok"},
            "connector": {"id": "abc", "scope": "Domain-Name,IPv4-Addr", "auto": True},
            "zetalytics": {
                "token": "zt",
                "mode": "light",
                "max_results": 25,
                "lookback_days": 90,
                "tsfield": "last_seen",
                "include_live_dns": False,
                "include_subdomains": False,
                "include_d8s": False,
            },
        }
    )

    assert config.zetalytics.mode == "light"
    assert config.zetalytics.max_results == 25
    assert config.zetalytics.include_live_dns is False
    assert config.zetalytics.include_subdomains is False


def test_to_helper_config_returns_dict():
    config = _make_loader(
        {
            "opencti": {"url": "http://localhost:8080", "token": "tok"},
            "connector": {"id": "abc", "scope": "Domain-Name"},
            "zetalytics": {"token": "zt"},
        }
    )
    result = config.to_helper_config()
    assert isinstance(result, dict)
    assert "opencti" in result


@pytest.mark.parametrize(
    ("lookback_days", "expected_suffix"),
    [
        (365, "(1 year)"),
        (730, "(2 years)"),
        (1825, "(5 years)"),
        (90, "(3 months)"),
        (180, "(6 months)"),
        (1, "(1 day)"),
        (100, "(100 days)"),
        (912, "(2.5 years)"),
        (913, "(2.5 years)"),
        (370, "(1 year)"),
        (1000, "(2.7 years)"),
    ],
)
def test_connector_name_gets_lookback_period_appended(lookback_days, expected_suffix):
    """The connector name shown in OpenCTI should include a human-readable lookback period."""
    config = _make_loader(
        {
            "opencti": {"url": "http://localhost:8080", "token": "tok"},
            "connector": {
                "id": "abc",
                "name": "Zetalytics DNS - Deep Investigation",
                "scope": "Domain-Name",
            },
            "zetalytics": {"token": "zt", "lookback_days": lookback_days},
        }
    )
    assert config.connector.name == f"Zetalytics DNS - Deep Investigation {expected_suffix}"


def test_connector_name_suffix_not_duplicated_on_repeated_validation():
    """Re-running validation (e.g. via model_copy/model_validate) shouldn't double-append the suffix."""
    config = _make_loader(
        {
            "opencti": {"url": "http://localhost:8080", "token": "tok"},
            "connector": {"id": "abc", "scope": "Domain-Name"},
            "zetalytics": {"token": "zt", "lookback_days": 365},
        }
    )
    assert config.connector.name.count("(1 year)") == 1
