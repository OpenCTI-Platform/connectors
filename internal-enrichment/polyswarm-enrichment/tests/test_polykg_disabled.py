"""Regression tests for polykg enrichment disabled via blank POLYKG_API_URL.

Guards the bug where a blank ``POLYKG_API_URL`` still built a schemeless
``/v3/kg/profile`` URL and raised ``requests.exceptions.MissingSchema`` on
every malware-family lookup (logged as an ERROR per family). Disabled mode
must be silent: no HTTP attempt, no error, clean None/False returns.
"""

import polyswarm_enrichment.client_api as client_api
import pytest
from conftest import StubConfig, StubHelper
from polyswarm_enrichment.client_api import ConnectorClient


@pytest.fixture()
def no_kg_config():
    """StubConfig with polykg disabled (blank URL), like a default deployment."""
    cfg = StubConfig()
    cfg.polykg_api_url = ""
    return cfg


@pytest.fixture()
def kg_call_spy(monkeypatch):
    """Record any HTTP call client_api attempts; fail loud if polykg is hit."""
    calls = []

    def _record(method):
        def _spy(url, **kwargs):
            calls.append((method, url))
            raise AssertionError(
                f"polykg disabled but client attempted {method.upper()} {url!r}"
            )

        return _spy

    monkeypatch.setattr(client_api.requests, "get", _record("get"))
    monkeypatch.setattr(client_api.requests, "post", _record("post"))
    return calls


class TestPolykgDisabled:
    def test_init_makes_no_kg_call(self, no_kg_config, kg_call_spy):
        # Construction must not run the connectivity probe when disabled.
        ConnectorClient(StubHelper(), no_kg_config)
        assert kg_call_spy == []

    def test_disabled_flag_set(self, no_kg_config, kg_call_spy):
        client = ConnectorClient(StubHelper(), no_kg_config)
        assert client._polykg_enabled is False

    def test_get_profile_returns_none_without_call(self, no_kg_config, kg_call_spy):
        client = ConnectorClient(StubHelper(), no_kg_config)
        assert client.get_profile("FunkSec") is None
        assert kg_call_spy == []

    def test_has_profiles_returns_false_without_call(self, no_kg_config, kg_call_spy):
        client = ConnectorClient(StubHelper(), no_kg_config)
        assert client.has_profiles() is False
        assert kg_call_spy == []

    def test_fetch_attack_patterns_returns_none_without_call(
        self, no_kg_config, kg_call_spy
    ):
        client = ConnectorClient(StubHelper(), no_kg_config)
        assert client.fetch_attack_patterns() is None
        assert kg_call_spy == []


class TestPolykgEnabledStillWorks:
    """Sanity check the guard does not break the normal (URL set) path."""

    def test_enabled_flag_true(self, stub_config, mock_polykg):
        client = ConnectorClient(StubHelper(), stub_config)
        assert client._polykg_enabled is True
        assert client.has_profiles() is True
