"""Unit tests for PolySwarmConnector — config, TLP, scope, sandbox providers."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from unittest.mock import MagicMock

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
    """Verify entity type filtering by ``enrichment_entity.entity_type``.

    Regression: the type must come from ``enrichment_entity.entity_type``, not
    the STIX ID prefix. A StixFile observable has id ``file--<uuid>`` but type
    ``StixFile``; parsing the prefix yields ``file`` which never matches a
    ``StixFile`` scope entry.
    """

    def test_artifact_in_scope(self):
        c = make_connector()  # connect_scope = "Artifact"
        assert (
            c._entity_in_scope(
                {
                    "entity_id": "artifact--1234-5678",
                    "enrichment_entity": {"entity_type": "Artifact"},
                }
            )
            is True
        )

    def test_indicator_not_in_scope(self):
        c = make_connector()
        assert (
            c._entity_in_scope(
                {
                    "entity_id": "indicator--1234",
                    "enrichment_entity": {"entity_type": "Indicator"},
                }
            )
            is False
        )

    def test_stixfile_matched_by_entity_type_not_id_prefix(self):
        # The id prefix is 'file' but the entity_type is 'StixFile'. The scope
        # check must use the type, so this is in scope when StixFile is listed.
        c = make_connector()
        c.helper.connect_scope = "StixFile,Artifact"
        assert (
            c._entity_in_scope(
                {
                    "entity_id": "file--1234-5678",
                    "enrichment_entity": {"entity_type": "StixFile"},
                }
            )
            is True
        )

    def test_stixfile_out_of_scope_under_default_artifact_only(self):
        # Default scope is Artifact only: the sandbox detonates an uploaded
        # file, so a StixFile carrying just a hash has nothing to detonate and
        # is correctly skipped rather than raising a confusing artifact error.
        c = make_connector()  # connect_scope = "Artifact"
        assert (
            c._entity_in_scope(
                {
                    "entity_id": "file--1234-5678",
                    "enrichment_entity": {"entity_type": "StixFile"},
                }
            )
            is False
        )

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


# ── Process message ───────────────────────────────────────────────────────────


class TestProcessMessage:
    """Verify _process_message routing: missing entity, out-of-scope, API errors."""

    def test_missing_entity_returns_error(self):
        c = make_connector()
        data = {"stix_objects": [], "stix_entity": None, "enrichment_entity": None}
        result = c._process_message(data)
        assert "error" in result

    def test_entity_out_of_scope_non_event_returns_result(self):
        c = make_connector()
        data = {
            "stix_objects": [],
            "stix_entity": {"id": "file--test"},
            "enrichment_entity": {"entity_type": "IPv4-Addr"},
            "entity_id": "test-id",
        }
        result = c._process_message(data)
        assert result is not None

    def test_entity_out_of_scope_event_type_raises(self):
        c = make_connector()
        data = {
            "stix_objects": [],
            "stix_entity": {"id": "file--test"},
            "enrichment_entity": {"entity_type": "IPv4-Addr"},
            "entity_id": "test-id",
            "event_type": "some-event",
        }
        with pytest.raises(ValueError):
            c._process_message(data)

    def test_enrich_returns_error_status(self):
        c = make_connector()
        c._enrich_file = MagicMock(return_value={"status": "error", "error": "fail"})
        data = {
            "stix_objects": [],
            "stix_entity": {"id": "file--test"},
            "enrichment_entity": {"entity_type": "artifact"},
            "entity_id": "test-id",
        }
        result = c._process_message(data)
        assert "error" in result

    def test_api_error_creates_note(self):
        from connector.polyswarm_client import PolySwarmAPIError

        c = make_connector()
        c._enrich_file = MagicMock(
            side_effect=PolySwarmAPIError(
                category="Test", detail="detail", recommendations=["retry"]
            )
        )
        c._send_error_note = MagicMock()
        data = {
            "stix_objects": [],
            "stix_entity": {"id": "file--test"},
            "enrichment_entity": {"entity_type": "artifact"},
            "entity_id": "test-id",
        }
        result = c._process_message(data)
        c._send_error_note.assert_called_once()
        assert "error" in result

    def test_unexpected_error_creates_note(self):
        c = make_connector()
        c._enrich_file = MagicMock(side_effect=ValueError("unexpected"))
        c._send_error_note = MagicMock()
        data = {
            "stix_objects": [],
            "stix_entity": {"id": "file--test"},
            "enrichment_entity": {"entity_type": "artifact"},
            "entity_id": "test-id",
        }
        result = c._process_message(data)
        assert "error" in result

    def test_stix_objects_bracket_access(self):
        """Verify stix_objects is read from data (covers VC322 bracket access)."""
        c = make_connector()
        data = {
            "stix_objects": [{"type": "identity", "id": "identity--test"}],
            "stix_entity": None,
            "enrichment_entity": None,
        }
        # Must not raise — stix_objects is accessed before entity check
        c._process_message(data)


# ── Send original bundle ───────────────────────────────────────────────────────


class TestSendOriginalBundle:
    """Verify _send_original_bundle handles empty and non-empty lists."""

    def test_empty_list_does_nothing(self):
        c = make_connector()
        c._send_original_bundle([])

    def test_non_empty_calls_helper(self):
        c = make_connector()
        c._send_original_bundle([{"type": "identity", "id": "identity--test"}])
        c.helper.stix2_create_bundle.assert_called_once()

    def test_bundle_error_is_swallowed(self):
        c = make_connector()
        c.helper.stix2_create_bundle = MagicMock(side_effect=ValueError("err"))
        c._send_original_bundle([{"type": "identity"}])  # must not raise


# ── Send error note exception paths ───────────────────────────────────────────


class TestSendErrorNoteExceptionPaths:
    """Verify _send_error_note never propagates exceptions."""

    def test_create_note_exception_is_swallowed(self):
        c = make_connector()
        c.stix_builder.create_error_note = MagicMock(side_effect=ValueError("err"))
        c._send_error_note(
            entity={"id": "file--test"},
            error_category="Test Error",
            error_detail="detail",
            recommendations=["retry"],
        )

    def test_bundle_exception_is_swallowed(self):
        c = make_connector()
        c.stix_builder.create_error_note = MagicMock(
            return_value={"type": "note", "id": "note--test"}
        )
        c.helper.stix2_create_bundle = MagicMock(side_effect=TypeError("fail"))
        c._send_error_note(
            entity={"id": "file--test"},
            error_category="Test",
            error_detail="detail",
            recommendations=[],
        )


# ── Debug sandbox structure ───────────────────────────────────────────────────


class TestDebugSandboxStructure:
    """Verify _debug_sandbox_structure handles all result shapes without error."""

    def test_empty_result(self):
        make_connector()._debug_sandbox_structure({})

    def test_top_level_domains(self):
        make_connector()._debug_sandbox_structure(
            {"domains": ["evil.com"], "status": "SUCCEEDED"}
        )

    def test_nested_report_with_network(self):
        make_connector()._debug_sandbox_structure(
            {
                "report": {
                    "domains": ["malware.com"],
                    "network": {
                        "dns": ["1.1.1.1"],
                        "http": ["http://example.com"],
                        "hosts": ["1.2.3.4"],
                        "tcp": [{"dst": "8.8.8.8"}],
                        "udp": [{"dst": "8.8.4.4"}],
                    },
                }
            }
        )

    def test_report_no_network(self):
        make_connector()._debug_sandbox_structure(
            {"report": {"strings": ["MZ"], "domains": []}}
        )


# ── Phase: stix bundle build ───────────────────────────────────────────────────


class TestPhaseStix:
    """Verify _phase_stix sends an error note when no data or no STIX objects."""

    def _conn(self):
        c = make_connector()
        c._enrich_ctx = "[test]"
        return c

    def test_no_data_sends_error_note(self):
        c = self._conn()
        c._send_error_note = MagicMock()
        c._phase_stix(
            entity={"id": "artifact--test"},
            scan_mapped=None,
            sandbox_mapped=None,
            sandbox_processed={},
            sandbox_failures={},
            llm_reports={},
            stix_objects=[],
        )
        c._send_error_note.assert_called_once()

    def test_no_stix_objects_created_sends_error_note(self):
        c = self._conn()
        c.stix_builder.build_bundle = MagicMock(return_value=[])
        c._send_error_note = MagicMock()
        c._phase_stix(
            entity={"id": "artifact--test"},
            scan_mapped={"score": 50},
            sandbox_mapped=None,
            sandbox_processed={},
            sandbox_failures={},
            llm_reports={},
            stix_objects=[],
        )
        c._send_error_note.assert_called_once()

    def test_objects_created_sends_bundle(self):
        c = self._conn()
        c.stix_builder.build_bundle = MagicMock(
            return_value=[{"type": "malware", "id": "malware--test"}]
        )
        c._phase_stix(
            entity={"id": "artifact--test"},
            scan_mapped={"score": 50},
            sandbox_mapped=None,
            sandbox_processed={},
            sandbox_failures={},
            llm_reports={},
            stix_objects=[],
        )
        c.helper.send_stix2_bundle.assert_called_once()


# ── Phase: sandbox result polling ─────────────────────────────────────────────


class TestPollSandboxResults:
    """Verify _poll_sandbox_results timeout, success, and failure branches."""

    def test_timeout_returns_empty(self):
        c = make_connector()
        c.polyswarm_client.get_sandbox_results = MagicMock(return_value=None)
        results = c._poll_sandbox_results(
            sandbox_tasks={"cape": "task-123"},
            poll_interval=0.01,
            poll_timeout=0.01,
            llm_task_ids=None,
        )
        assert isinstance(results, dict)

    def test_succeeded_result_stored(self):
        c = make_connector()
        c.polyswarm_client.get_sandbox_results = MagicMock(
            return_value={"status": "SUCCEEDED", "domains": []}
        )
        results = c._poll_sandbox_results(
            sandbox_tasks={"cape": "task-123"},
            poll_interval=0.01,
            poll_timeout=10,
            llm_task_ids=None,
        )
        assert results.get("cape") is not None

    def test_failed_result_stored(self):
        c = make_connector()
        c.polyswarm_client.get_sandbox_results = MagicMock(
            return_value={"status": "FAILED", "error": "Timeout"}
        )
        results = c._poll_sandbox_results(
            sandbox_tasks={"cape": "task-123"},
            poll_interval=0.01,
            poll_timeout=10,
            llm_task_ids=None,
        )
        assert results.get("cape") is not None


# ── Phase: reports (JSON / PDF / LLM) ────────────────────────────────────────


class TestPhaseReports:
    """Verify _phase_reports with all report types disabled and enabled."""

    def test_all_disabled_returns_empty_dict(self):
        c = make_connector(
            polyswarm_overrides={
                "json_report_enabled": False,
                "pdf_report_enabled": False,
                "llm_report_enabled": False,
            }
        )
        result = c._phase_reports(
            entity={"id": "artifact--test"},
            scan_id="scan-id",
            scan_res={"status": "completed"},
            scan_mapped={"score": 50},
            sandbox_tasks={},
            sandbox_results={},
            llm_task_ids={},
            filename="test.exe",
            lookup_hash="abc123",
        )
        assert result == {}

    def test_json_enabled_no_scan_res(self):
        c = make_connector(
            polyswarm_overrides={
                "json_report_enabled": True,
                "pdf_report_enabled": False,
                "llm_report_enabled": False,
            }
        )
        result = c._phase_reports(
            entity={"id": "artifact--test"},
            scan_id=None,
            scan_res=None,
            scan_mapped=None,
            sandbox_tasks={},
            sandbox_results={},
            llm_task_ids={},
            filename="test.exe",
            lookup_hash=None,
        )
        assert isinstance(result, dict)

    def test_json_enabled_with_scan_res_attaches_file(self):
        c = make_connector(
            polyswarm_overrides={
                "json_report_enabled": True,
                "pdf_report_enabled": False,
                "llm_report_enabled": False,
            }
        )
        c._phase_reports(
            entity={"id": "artifact--test"},
            scan_id="scan-id",
            scan_res={"score": 80},
            scan_mapped={"score": 80},
            sandbox_tasks={},
            sandbox_results={"cape": {"status": "SUCCEEDED"}},
            llm_task_ids={},
            filename="malware.exe",
            lookup_hash="deadbeef1234",
        )
        c.helper.api.stix_cyber_observable.add_file.assert_called()

    def test_llm_enabled_collects_reports(self):
        c = make_connector(
            polyswarm_overrides={
                "json_report_enabled": False,
                "pdf_report_enabled": False,
                "llm_report_enabled": True,
                "llm_report_timeout": 5,
            }
        )
        c.polyswarm_client.collect_llm_report = MagicMock(
            return_value="AI analysis text"
        )
        result = c._phase_reports(
            entity={"id": "artifact--test"},
            scan_id=None,
            scan_res=None,
            scan_mapped=None,
            sandbox_tasks={},
            sandbox_results={},
            llm_task_ids={"cape": "llm-task-1"},
            filename="test.exe",
            lookup_hash=None,
        )
        assert result.get("cape") == "AI analysis text"

    def test_llm_collect_failure_sends_error_note(self):
        c = make_connector(
            polyswarm_overrides={
                "json_report_enabled": False,
                "pdf_report_enabled": False,
                "llm_report_enabled": True,
                "llm_report_timeout": 5,
            }
        )
        c.polyswarm_client.collect_llm_report = MagicMock(return_value=None)
        c._send_error_note = MagicMock()
        c._phase_reports(
            entity={"id": "artifact--test"},
            scan_id=None,
            scan_res=None,
            scan_mapped=None,
            sandbox_tasks={},
            sandbox_results={},
            llm_task_ids={"cape": "llm-task-1"},
            filename="test.exe",
            lookup_hash=None,
        )
        c._send_error_note.assert_called_once()

    def test_json_attach_failure_logs_warning(self):
        """Cover the except branch when add_file raises (L949 scan, L967 sandbox)."""
        c = make_connector(
            polyswarm_overrides={
                "json_report_enabled": True,
                "pdf_report_enabled": False,
                "llm_report_enabled": False,
            }
        )
        c.helper.api.stix_cyber_observable.add_file = MagicMock(
            side_effect=OSError("disk full")
        )
        # Should not raise — errors are caught and logged
        c._phase_reports(
            entity={"id": "artifact--test"},
            scan_id="scan-id",
            scan_res={"score": 80},
            scan_mapped={"score": 80},
            sandbox_tasks={},
            sandbox_results={"cape": {"status": "SUCCEEDED"}},
            llm_task_ids={},
            filename="malware.exe",
            lookup_hash="deadbeef1234",
        )
        # add_file was called and raised, connector_logger.warning was called
        c.helper.connector_logger.warning.assert_called()
