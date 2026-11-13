"""Integration tests for enrichment flow — exercises the decomposed phase methods.

Each test class targets a single phase method (download, submit, poll, stix)
to verify correct behaviour in isolation, plus TestEnrichFileOrchestration
verifies the full pipeline end-to-end with mocked dependencies.
"""

from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk.models.enums import TLPLevel
from pycti import OpenCTIConnectorHelper

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


# ── TLP check ───────────────────────────────────────────────────────────────
# make_connector() wires pycti's real check_max_tlp, so these tests run against
# its actual contract: one TLP definition such as "TLP:GREEN" (#7955).


def _marked(*definitions):
    entity = _opencti_entity()
    entity["objectMarking"] = [
        {
            "standard_id": f"marking-definition--{i}",
            "definition_type": definition.split(":")[0],
            "definition": definition,
        }
        for i, definition in enumerate(definitions)
    ]
    return entity


def _reaches_download(c, opencti_entity):
    """Run _enrich_file with download disabled; True if it got past the TLP check."""
    c.artifact_handler.download_artifact = MagicMock(
        return_value=(None, "Download disabled")
    )
    result = c._enrich_file(
        ENTITY_ID, _entity(), opencti_entity, [{"type": "identity"}]
    )
    return (
        c.artifact_handler.download_artifact.called
        and "disabled" in (result.get("error") or "").lower()
    )


class TestTlpCheck:
    """check_max_tlp must receive a TLP name, not the list of marking ids."""

    def test_real_helper_rejects_a_list_of_marking_ids(self):
        """Guards the contract the old code got wrong."""
        with pytest.raises(AttributeError):
            OpenCTIConnectorHelper.check_max_tlp(
                ["marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"],
                "TLP:AMBER",
            )

    @pytest.mark.parametrize("level", list(TLPLevel))
    def test_every_configurable_max_tlp_is_accepted_by_the_helper(self, level):
        """Mirrors how __init__ formats CONNECTOR_MAX_TLP for check_max_tlp."""
        max_tlp = f"TLP:{level.upper()}"
        assert OpenCTIConnectorHelper.check_max_tlp("TLP:CLEAR", max_tlp)

    def test_connector_uses_the_real_helper(self):
        c = make_connector()
        assert c.helper.check_max_tlp is OpenCTIConnectorHelper.check_max_tlp

    @pytest.mark.parametrize("tlp", ["TLP:CLEAR", "TLP:WHITE", "TLP:GREEN"])
    def test_marked_artifact_within_max_tlp_is_enriched(self, tlp):
        c = make_connector()
        assert _reaches_download(c, _marked(tlp, "PAP:GREEN"))

    def test_non_tlp_marking_only_is_enriched(self):
        c = make_connector()
        assert _reaches_download(c, _marked("PAP:RED"))

    def test_unmarked_artifact_is_enriched(self):
        c = make_connector()
        assert _reaches_download(c, _opencti_entity())

    @pytest.mark.parametrize(
        "markings", [("TLP:RED",), ("TLP:GREEN", "TLP:RED"), ("TLP:AMBER+STRICT",)]
    )
    def test_marked_artifact_above_max_tlp_is_skipped(self, markings):
        c = make_connector()
        result = c._enrich_file(
            ENTITY_ID, _entity(), _marked(*markings), [{"type": "identity"}]
        )
        assert result["status"] == "skipped"
        c.artifact_handler.download_artifact.assert_not_called()

    @pytest.mark.parametrize("tlp, skipped", [("TLP:RED", True), ("TLP:GREEN", False)])
    def test_tlp_check_without_stix_objects(self, tlp, skipped):
        """An empty stix_objects list must not bypass the TLP limit (#8351)."""
        c = make_connector()
        c.artifact_handler.download_artifact = MagicMock(
            return_value=(None, "Download disabled")
        )
        result = c._enrich_file(ENTITY_ID, _entity(), _marked(tlp), [])
        if skipped:
            assert result["status"] == "skipped"
            c.artifact_handler.download_artifact.assert_not_called()
        else:
            c.artifact_handler.download_artifact.assert_called_once()

    @pytest.mark.parametrize(
        "marking",
        [
            {
                "x_opencti_definition_type": "TLP",
                "x_opencti_definition": "TLP:AMBER+STRICT",
            },
            {"definition_type": "tlp", "definition": {"tlp": "red"}},
            None,
        ],
    )
    def test_bundled_tlp_marking_is_skipped(self, marking):
        """Bundle-only TLP markings are resolved on the file path too."""
        c = make_connector()
        opencti_entity = _opencti_entity()
        opencti_entity["standard_id"] = ENTITY_ID
        entity = _entity()
        stix_objects = [entity]
        if marking is None:
            # Well-known TLP:RED id with no definition object in the bundle
            entity["object_marking_refs"] = [
                "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
            ]
        else:
            marking = dict(
                marking,
                type="marking-definition",
                id="marking-definition--00000000-0000-4000-8000-000000000002",
            )
            entity["object_marking_refs"] = [marking["id"]]
            stix_objects.append(marking)
        result = c._enrich_file(ENTITY_ID, entity, opencti_entity, stix_objects)
        assert result["status"] == "skipped"
        c.artifact_handler.download_artifact.assert_not_called()

    def test_stix_entity_refs_are_checked(self):
        """The STIX entity's refs count even when the OpenCTI ids differ."""
        c = make_connector()
        marking = {
            "type": "marking-definition",
            "id": "marking-definition--00000000-0000-4000-8000-000000000003",
            "name": "TLP:RED",
        }
        entity = _entity()
        entity["object_marking_refs"] = [marking["id"]]
        opencti_entity = _opencti_entity()
        opencti_entity["standard_id"] = "artifact--00000000-0000-0000-0000-0000000000ff"
        result = c._enrich_file(ENTITY_ID, entity, opencti_entity, [marking])
        assert result["status"] == "skipped"
        c.artifact_handler.download_artifact.assert_not_called()

    def test_skipped_artifact_forwards_original_bundle(self):
        """A TLP skip must still forward the bundle so playbooks do not stall."""
        c = make_connector()
        c._entity_in_scope = MagicMock(return_value=True)
        c._send_original_bundle = MagicMock()
        stix_objects = [{"type": "identity"}]
        c.artifact_handler.download_artifact = MagicMock()
        c._process_message(
            {
                "enrichment_entity": _marked("TLP:RED"),
                "stix_entity": _entity(),
                "stix_objects": stix_objects,
                "entity_id": ENTITY_ID,
            }
        )
        c._send_original_bundle.assert_called_once_with(stix_objects)
        c.artifact_handler.download_artifact.assert_not_called()


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


# ── Public community guard ──────────────────────────────────────────────────


class TestPublicCommunityGuard:
    """Uploads to the public community need POLYSWARM_ALLOW_PUBLIC_COMMUNITY=true."""

    @pytest.mark.parametrize(
        "community",
        ["default", "DEFAULT", " default ", "", "public", "Public", "mainnet1"],
    )
    def test_public_community_without_opt_in_is_refused(self, community):
        c = make_connector(
            polyswarm_overrides={
                "community": community,
                "allow_public_community": False,
            }
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(b"data", None))
        c.polyswarm_client.submit_file_async = MagicMock(return_value="scan-001")

        result = c._enrich_file(ENTITY_ID, _entity(), _opencti_entity(), [])

        assert result["status"] == "error"
        assert "public community" in result["error"]
        c.artifact_handler.download_artifact.assert_not_called()
        c.polyswarm_client.submit_file_async.assert_not_called()
        c.polyswarm_client.submit_sandbox_async.assert_not_called()
        c.stix_builder.create_error_note.assert_called()

    def test_public_community_with_opt_in_is_uploaded(self):
        c = make_connector(
            polyswarm_overrides={
                "community": "default",
                "allow_public_community": True,
            }
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(b"data", None))
        c.polyswarm_client.submit_file_async = MagicMock(return_value=None)

        c._enrich_file(ENTITY_ID, _entity(), _opencti_entity(), [])

        c.polyswarm_client.submit_file_async.assert_called_once()

    def test_private_community_is_uploaded_without_opt_in(self):
        c = make_connector(
            polyswarm_overrides={
                "community": "acme-private",
                "allow_public_community": False,
            }
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(b"data", None))
        c.polyswarm_client.submit_file_async = MagicMock(return_value=None)

        c._enrich_file(ENTITY_ID, _entity(), _opencti_entity(), [])

        c.polyswarm_client.submit_file_async.assert_called_once()

    def test_opt_in_defaults_to_false(self):
        from connector.models.configs.settings import PolySwarmConfig

        assert PolySwarmConfig.model_fields["allow_public_community"].default is False
