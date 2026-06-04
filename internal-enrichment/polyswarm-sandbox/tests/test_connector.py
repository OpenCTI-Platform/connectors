"""Unit tests for PolySwarmConnector — config, TLP, scope, sandbox providers."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import MagicMock

import pytest

ENTITY_ID = "artifact--00000000-0000-0000-0000-000000000001"


@pytest.fixture
def minimal_stix_entity():
    return {
        "type": "artifact",
        "spec_version": "2.1",
        "id": ENTITY_ID,
        "hashes": {"SHA-256": "a" * 64},
    }


def _mock_polyswarm_config(**overrides):
    """Create a mock for config.polyswarm with sensible defaults.

    Every PolySwarm setting is given a safe default so individual tests only
    need to override the specific knob they're exercising.
    """
    defaults = {
        "api_key": MagicMock(get_secret_value=MagicMock(return_value="test-key")),
        "api_url": "https://api.polyswarm.network/v3",
        "community": "default",
        "timeout": 300,
        "sandbox_enabled": False,
        "sandbox_provider": "cape",
        "sandbox_vm_cape": "win-10",
        "sandbox_vm_triage": "win11",
        "sandbox_vm": None,
        "sandbox_network_enabled": True,
        "sandbox_timeout": 60,
        "poll_interval": 5,
        "poll_timeout": 30,
        "json_report_enabled": False,
        "pdf_report_enabled": False,
        "llm_report_enabled": False,
        "llm_report_timeout": 30,
        "min_polyscore": 50,
        "create_indicators": True,
        "create_observables": True,
        "max_file_size": 33554432,
        "download_artifacts": True,
        "polykg_api_url": None,
        "max_tlp": "TLP:AMBER",
        "replace_with_lower_score": True,
    }
    defaults.update(overrides)
    m = MagicMock()
    for k, v in defaults.items():
        setattr(m, k, v)
    return m


def _mock_connector_config(**overrides):
    """Create a mock for config.connector with sensible defaults.

    Note: max_tlp and replace_with_lower_score live in config.polyswarm,
    NOT here — see PolySwarmConfig in settings.py.
    """
    defaults = {}
    defaults.update(overrides)
    m = MagicMock()
    for k, v in defaults.items():
        setattr(m, k, v)
    return m


def make_connector(polyswarm_overrides=None, connector_overrides=None):
    """Create a PolySwarmConnector with mocked dependencies.

    Uses ``__new__`` + manual attribute assignment to bypass ``__init__``
    (which would try to instantiate a real PolySwarmClient / SDK).
    """
    from connector.polyswarm_connector import PolySwarmConnector

    c = PolySwarmConnector.__new__(PolySwarmConnector)
    c.helper = MagicMock()
    c.helper.connect_scope = "Artifact"
    c.helper.stix2_create_bundle = MagicMock(
        side_effect=lambda objs: {"type": "bundle", "objects": objs}
    )
    c.helper.send_stix2_bundle = MagicMock(return_value=["bundle-1"])
    c.helper.check_max_tlp = MagicMock(return_value=True)

    config = MagicMock()
    config.polyswarm = _mock_polyswarm_config(**(polyswarm_overrides or {}))
    config.connector = _mock_connector_config(**(connector_overrides or {}))
    c.config = config

    # Set attributes normally assigned in __init__ from config.polyswarm
    c.max_tlp = config.polyswarm.max_tlp
    c.replace_with_lower_score = config.polyswarm.replace_with_lower_score

    c.polyswarm_client = MagicMock()
    c.stix_builder = MagicMock()
    c.artifact_handler = MagicMock()
    c._local = MagicMock()
    return c


# ── Pydantic Config ─────────────────────────────────────────────────────────


class TestPydanticConfig:
    """Verify ConnectorSettings loads from env vars and exposes correct defaults.

    These tests confirm the Pydantic model (connectors_sdk base) correctly
    reads OPENCTI_*, CONNECTOR_*, and POLYSWARM_* env vars and produces a
    dict compatible with OpenCTIConnectorHelper via ``to_helper_config()``.
    """

    def test_config_loads_with_env_vars(self, monkeypatch):
        ConnectorSettings = pytest.importorskip(
            "connector.models.configs.settings", reason="connectors_sdk unavailable"
        ).ConnectorSettings
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000001")
        monkeypatch.setenv("POLYSWARM_API_KEY", "test-api-key")

        config = ConnectorSettings()
        assert str(config.opencti.url).rstrip("/") == "http://localhost:8080"
        assert config.opencti.token == "test-token"
        assert config.polyswarm.api_key.get_secret_value() == "test-api-key"

    def test_config_defaults(self, monkeypatch):
        ConnectorSettings = pytest.importorskip(
            "connector.models.configs.settings", reason="connectors_sdk unavailable"
        ).ConnectorSettings
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000002")
        monkeypatch.setenv("POLYSWARM_API_KEY", "test-key")

        config = ConnectorSettings()
        assert config.polyswarm.sandbox_provider == "cape"
        assert config.polyswarm.sandbox_enabled is True
        assert config.polyswarm.poll_interval == 30
        assert config.connector.type == "INTERNAL_ENRICHMENT"

    def test_model_dump_pycti(self, monkeypatch):
        ConnectorSettings = pytest.importorskip(
            "connector.models.configs.settings", reason="connectors_sdk unavailable"
        ).ConnectorSettings
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000003")
        monkeypatch.setenv("POLYSWARM_API_KEY", "test-key")

        config = ConnectorSettings()
        dumped = config.to_helper_config()
        assert "opencti" in dumped
        assert "connector" in dumped
        assert dumped["connector"]["type"] == "INTERNAL_ENRICHMENT"


# ── Entity Scope ─────────────────────────────────────────────────────────────


class TestEntityScope:
    """Verify entity type filtering — only Artifact/StixFile should pass."""

    def test_artifact_in_scope(self):
        c = make_connector()
        assert c._entity_in_scope({"entity_id": "artifact--1234-5678"}) is True

    def test_indicator_not_in_scope(self):
        c = make_connector()
        assert c._entity_in_scope({"entity_id": "indicator--1234"}) is False

    def test_skips_non_artifact(self):
        c = make_connector()
        result = c._process_message(
            {
                "entity_id": "indicator--1234",
                "entity_type": "Indicator",
                "enrichment_entity": {"entity_type": "Indicator"},
                "stix_objects": [],
            }
        )
        assert "not in scope" in result.lower()


# ── Sandbox Providers ────────────────────────────────────────────────────────


class TestSandboxProviders:
    """Verify _get_sandbox_providers resolves 'cape', 'triage', 'both', and invalid values.

    The method now validates against the API's available providers via
    ``polyswarm_client.get_provider_slugs()``.
    """

    def test_cape_only(self):
        c = make_connector(polyswarm_overrides={"sandbox_provider": "cape"})
        c.polyswarm_client.get_provider_slugs.return_value = ["cape", "triage"]
        assert c._get_sandbox_providers() == ["cape"]

    def test_triage_only(self):
        c = make_connector(polyswarm_overrides={"sandbox_provider": "triage"})
        c.polyswarm_client.get_provider_slugs.return_value = ["cape", "triage"]
        assert c._get_sandbox_providers() == ["triage"]

    def test_both(self):
        c = make_connector(polyswarm_overrides={"sandbox_provider": "both"})
        c.polyswarm_client.get_provider_slugs.return_value = ["cape", "triage"]
        assert c._get_sandbox_providers() == ["cape", "triage"]

    def test_unknown_defaults_to_first_available(self):
        c = make_connector(polyswarm_overrides={"sandbox_provider": "invalid"})
        c.polyswarm_client.get_provider_slugs.return_value = ["cape", "triage"]
        assert c._get_sandbox_providers() == ["cape"]

    def test_unknown_no_api_providers_defaults_to_cape(self):
        c = make_connector(polyswarm_overrides={"sandbox_provider": "invalid"})
        c.polyswarm_client.get_provider_slugs.return_value = []
        assert c._get_sandbox_providers() == ["cape"]

    def test_both_with_empty_api_falls_back(self):
        c = make_connector(polyswarm_overrides={"sandbox_provider": "both"})
        c.polyswarm_client.get_provider_slugs.return_value = []
        assert c._get_sandbox_providers() == ["cape", "triage"]


# ── VM Slug ──────────────────────────────────────────────────────────────────


class TestVMSlug:
    """Verify VM slug resolution.

    Priority: legacy sandbox_vm override > API default (prefers Windows) > hardcoded fallback.
    """

    def test_legacy_sandbox_vm_overrides_api(self):
        c = make_connector(polyswarm_overrides={"sandbox_vm": "legacy-vm"})
        c.polyswarm_client.get_default_vm_for_provider.return_value = "api-windows-vm"
        assert c._get_vm_for_provider("cape") == "legacy-vm"

    def test_api_default_used_when_no_override(self):
        c = make_connector(polyswarm_overrides={"sandbox_vm": None})
        c.polyswarm_client.get_default_vm_for_provider.return_value = "api-windows-vm"
        assert c._get_vm_for_provider("cape") == "api-windows-vm"

    def test_api_default_used_for_triage(self):
        c = make_connector(polyswarm_overrides={"sandbox_vm": None})
        c.polyswarm_client.get_default_vm_for_provider.return_value = (
            "windows11-21h2-x64"
        )
        assert c._get_vm_for_provider("triage") == "windows11-21h2-x64"

    def test_hardcoded_fallback_when_api_unavailable(self):
        c = make_connector(polyswarm_overrides={"sandbox_vm": None})
        c.polyswarm_client.get_default_vm_for_provider.return_value = None
        assert c._get_vm_for_provider("cape") == "win-10-build-19041"

    def test_hardcoded_fallback_for_unknown_provider(self):
        c = make_connector(polyswarm_overrides={"sandbox_vm": None})
        c.polyswarm_client.get_default_vm_for_provider.return_value = None
        assert c._get_vm_for_provider("newprovider") == "win-10-build-19041"
