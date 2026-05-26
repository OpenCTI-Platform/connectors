"""Integration tests for enrichment flow — exercises the decomposed phase methods.

Each test class targets a single phase method (download, submit, poll, stix)
to verify correct behaviour in isolation, plus TestEnrichFileOrchestration
verifies the full pipeline end-to-end with mocked dependencies.
"""

from unittest.mock import MagicMock, patch

import pytest

from tests.test_connector import make_connector

ENTITY_ID = "artifact--00000000-0000-0000-0000-000000000001"
HASH_SHA256 = "a" * 64


def _entity():
    return {
        "type": "artifact",
        "id": ENTITY_ID,
        "hashes": {"SHA-256": HASH_SHA256},
        "name": "sample.exe",
    }


def _opencti_entity():
    return {
        "entity_type": "Artifact",
        "importFiles": [
            {
                "id": "file-001",
                "name": "sample.exe",
                "size": 1024,
                "metaData": {"mimetype": "application/x-dosexec"},
            }
        ],
    }


# ── _phase_download ─────────────────────────────────────────────────────────


class TestPhaseDownload:
    """Verify artifact download, filename/password extraction, and error paths."""

    def test_success(self):
        c = make_connector()
        c.artifact_handler.download_artifact = MagicMock(
            return_value=(b"file-data", None)
        )
        file_data, filename, password, mime_type = c._phase_download(
            _entity(), _opencti_entity(), HASH_SHA256
        )
        assert file_data == b"file-data"
        assert filename == "sample.exe"
        assert mime_type == "application/x-dosexec"

    def test_download_error_raises(self):
        c = make_connector()
        c.artifact_handler.download_artifact = MagicMock(
            return_value=(None, "File too large")
        )
        with pytest.raises(ValueError, match="File too large"):
            c._phase_download(_entity(), _opencti_entity(), HASH_SHA256)

    def test_no_file_data_raises(self):
        c = make_connector()
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, None))
        with pytest.raises(ValueError, match="Could not download"):
            c._phase_download(_entity(), _opencti_entity(), HASH_SHA256)

    def test_password_extracted_from_entity(self):
        c = make_connector()
        c.artifact_handler.download_artifact = MagicMock(return_value=(b"data", None))
        entity = _entity()
        entity["decryption_key"] = "infected"
        _, _, password, _ = c._phase_download(entity, _opencti_entity(), HASH_SHA256)
        assert password == "infected"

    def test_fallback_filename(self):
        c = make_connector()
        c.artifact_handler.download_artifact = MagicMock(return_value=(b"data", None))
        oe = {"entity_type": "Artifact", "importFiles": []}
        entity = {
            "type": "artifact",
            "id": ENTITY_ID,
            "hashes": {"SHA-256": HASH_SHA256},
        }
        _, filename, _, _ = c._phase_download(entity, oe, HASH_SHA256)
        assert filename == HASH_SHA256  # falls back to lookup_hash


# ── _phase_submit ───────────────────────────────────────────────────────────


class TestPhaseSubmit:
    """Verify scan + sandbox submission, including sandbox-disabled and failure cases."""

    def test_scan_success_no_sandbox(self):
        c = make_connector(polyswarm_overrides={"sandbox_enabled": False})
        c.polyswarm_client.submit_file_async = MagicMock(return_value="scan-001")
        scan_id, sandbox_tasks = c._phase_submit(
            _entity(), b"data", "sample.exe", "application/octet-stream", None
        )
        assert scan_id == "scan-001"
        assert sandbox_tasks == {}

    def test_scan_failure_raises(self):
        c = make_connector()
        c.polyswarm_client.submit_file_async = MagicMock(return_value=None)
        with pytest.raises(ValueError, match="Scan submission"):
            c._phase_submit(_entity(), b"data", "sample.exe", None, None)

    def test_sandbox_submission(self):
        c = make_connector(
            polyswarm_overrides={"sandbox_enabled": True, "sandbox_provider": "cape"}
        )
        c.polyswarm_client.submit_file_async = MagicMock(return_value="scan-001")
        c.polyswarm_client.submit_sandbox_async = MagicMock(return_value="sb-001")
        c.polyswarm_client.get_provider_slugs = MagicMock(
            return_value=["cape", "triage"]
        )
        c.polyswarm_client.get_default_vm_for_provider = MagicMock(return_value=None)
        scan_id, sandbox_tasks = c._phase_submit(
            _entity(), b"data", "sample.exe", None, None
        )
        assert scan_id == "scan-001"
        assert "cape" in sandbox_tasks

    def test_sandbox_failure_non_fatal(self):
        c = make_connector(
            polyswarm_overrides={"sandbox_enabled": True, "sandbox_provider": "cape"}
        )
        c.polyswarm_client.submit_file_async = MagicMock(return_value="scan-001")
        c.polyswarm_client.submit_sandbox_async = MagicMock(return_value=None)
        c.polyswarm_client.get_provider_slugs = MagicMock(
            return_value=["cape", "triage"]
        )
        c.polyswarm_client.get_default_vm_for_provider = MagicMock(return_value=None)
        scan_id, sandbox_tasks = c._phase_submit(
            _entity(), b"data", "sample.exe", None, None
        )
        assert scan_id == "scan-001"
        assert sandbox_tasks == {}


# ── _phase_poll_scan ────────────────────────────────────────────────────────


class TestPhasePollScan:
    """Verify scan polling, timeout detection, and LLM report fire-on-success."""

    def test_scan_completes(self):
        c = make_connector(polyswarm_overrides={"llm_report_enabled": False})
        c.polyswarm_client.get_scan_results = MagicMock(return_value={"result": "ok"})
        with patch("time.sleep"):
            scan_res, llm_ids = c._phase_poll_scan(_entity(), "scan-001", 1, 10)
        assert scan_res == {"result": "ok"}
        assert llm_ids == {}

    def test_scan_timeout(self):
        c = make_connector(polyswarm_overrides={"llm_report_enabled": False})
        c.polyswarm_client.get_scan_results = MagicMock(return_value=None)
        with patch("time.sleep"), patch("time.monotonic", side_effect=[0, 0, 100, 100]):
            scan_res, _ = c._phase_poll_scan(_entity(), "scan-001", 1, 10)
        assert scan_res is None

    def test_fires_llm_on_success(self):
        c = make_connector(polyswarm_overrides={"llm_report_enabled": True})
        c.polyswarm_client.get_scan_results = MagicMock(return_value={"result": "ok"})
        c.polyswarm_client.create_llm_report = MagicMock(return_value="llm-001")
        with patch("time.sleep"):
            _, llm_ids = c._phase_poll_scan(_entity(), "scan-001", 1, 10)
        assert llm_ids.get("scan") == "llm-001"


# ── _phase_stix ─────────────────────────────────────────────────────────────


class TestPhaseStix:
    """Verify STIX bundle construction, playbook compat, and error-note on empty data."""

    def test_no_data_sends_error_note(self):
        c = make_connector()
        c._phase_stix(_entity(), None, None, {}, {}, {}, [])
        c.stix_builder.create_error_note.assert_called()

    def test_with_scan_data_builds_bundle(self):
        c = make_connector()
        scan_mapped = {"score": 85, "family": "Emotet"}
        author = {"type": "identity", "id": "identity--ps"}
        note = {"type": "note", "id": "note--1"}
        c.stix_builder.build_bundle = MagicMock(return_value=[author, note])
        c._phase_stix(_entity(), scan_mapped, None, {}, {}, {}, [])
        c.helper.send_stix2_bundle.assert_called_once()

    def test_playbook_compat_entity_in_bundle(self):
        c = make_connector()
        scan_mapped = {"score": 50}
        entity = _entity()
        c.stix_builder.build_bundle = MagicMock(
            return_value=[
                {"type": "identity", "id": "identity--ps"},
            ]
        )
        c._phase_stix(entity, scan_mapped, None, {}, {}, {}, [])
        # The entity should be included in the bundle for playbook compat
        call_args = c.helper.stix2_create_bundle.call_args[0][0]
        entity_ids = {o.get("id") for o in call_args}
        assert entity["id"] in entity_ids


# ── Full orchestration ──────────────────────────────────────────────────────


class TestEnrichFileOrchestration:
    """End-to-end tests through _enrich_file with all phases mocked."""

    def test_full_flow_success(self):
        c = make_connector(
            polyswarm_overrides={
                "sandbox_enabled": False,
                "llm_report_enabled": False,
                "json_report_enabled": False,
                "pdf_report_enabled": False,
            }
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(b"data", None))
        c.polyswarm_client.submit_file_async = MagicMock(return_value="scan-001")
        c.polyswarm_client.get_scan_results = MagicMock(
            return_value={"result": "detections", "failed": False}
        )
        c.stix_builder.build_bundle = MagicMock(
            return_value=[
                {"type": "identity", "id": "identity--ps"},
                {"type": "note", "id": "note--1"},
            ]
        )

        with patch("time.sleep"), patch(
            "connector.polyswarm_connector.ScanProcessor"
        ) as sp:
            sp.process.return_value = {"score": 80, "family": "TestMalware"}
            result = c._enrich_file(ENTITY_ID, _entity(), _opencti_entity(), [])

        assert result is None  # success
        c.helper.send_stix2_bundle.assert_called_once()

    def test_download_failure_returns_error(self):
        c = make_connector()
        c.artifact_handler.download_artifact = MagicMock(
            return_value=(None, "Download disabled")
        )
        result = c._enrich_file(ENTITY_ID, _entity(), _opencti_entity(), [])
        assert result["status"] == "error"
        assert "disabled" in result["error"].lower()

    def test_process_message_scope_check(self):
        c = make_connector()
        c.helper.connect_scope = "Artifact"
        result = c._process_message(
            {
                "entity_id": "indicator--1234",
                "enrichment_entity": {"entity_type": "Indicator"},
                "stix_objects": [],
            }
        )
        assert "not in scope" in result.lower()
