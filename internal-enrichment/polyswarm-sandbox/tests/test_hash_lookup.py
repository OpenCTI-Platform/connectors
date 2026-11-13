"""Sandbox reports by hash: StixFile lookup, Artifact reuse, detonate-by-hash.

Task shapes come from the SDK's own ``SandboxTask`` resource, fed with the
latest EICAR sandbox tasks fetched READ ONLY with ``sandbox_task_latest`` on
2026-11-10 (account numbers and upload URL scrubbed):

- fixtures/sandbox_task_latest_eicar_cape.json: CAPE, SUCCEEDED
- fixtures/sandbox_task_latest_eicar_triage.json: Triage, SUCCEEDED

Measured live the same day: sandbox_task_latest for a hash with no task
raises NotFoundException ("No tasks found."); search for a hash PolySwarm
does not hold raises NoResultsException.
"""

import copy
import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from connector.polyswarm_client import PolySwarmAPIError, PolySwarmClient
from connector.stix_builder import StixBuilder
from polyswarm_api import exceptions as ps_exceptions
from polyswarm_api import resources

from tests.conftest import EICAR_SHA256
from tests.test_connector import make_connector

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FILE_ID = "file--00000000-0000-0000-0000-0000000000f1"
ARTIFACT_ID = "artifact--00000000-0000-0000-0000-0000000000a1"
INSTANCE_ID = "41363621986537527"


def _fixture(name):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def _task(provider="cape", **changes):
    task = resources.SandboxTask(
        _fixture(f"sandbox_task_latest_eicar_{provider}.json")
    ).json
    task = copy.deepcopy(task)
    task.update(changes)
    return task


def _days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _stixfile(hashes=None):
    return {
        "type": "file",
        "spec_version": "2.1",
        "id": FILE_ID,
        "name": "eicar.com",
        "hashes": {"SHA-256": EICAR_SHA256} if hashes is None else hashes,
    }


def _opencti_file(entity_type="StixFile", **extra):
    return {"entity_type": entity_type, "standard_id": FILE_ID, **extra}


def _connector(latest=None, **overrides):
    """Connector with a mocked client.

    latest maps provider -> task. A provider left out has no task (the
    client's {}); map a provider to None for a failed lookup.
    """
    polyswarm = {
        "community": "acme-private",
        "allow_public_community": False,
        "sandbox_enabled": True,
        "sandbox_provider": "cape",
        "json_report_enabled": True,
        "pdf_report_enabled": True,
    }
    polyswarm.update(overrides)
    c = make_connector(polyswarm_overrides=polyswarm)
    c.helper.connect_scope = "Artifact,StixFile,Url"
    c.stix_builder = StixBuilder(helper=MagicMock())
    client = c.polyswarm_client
    client.get_provider_slugs = MagicMock(return_value=["cape", "triage"])
    client.get_default_vm_for_provider = MagicMock(return_value="win-10-build-19041")
    latest = {"cape": _task()} if latest is None else latest
    client.get_latest_sandbox_task = MagicMock(
        side_effect=lambda sha, prov: latest.get(prov, {})
    )
    client.find_instance_by_hash = MagicMock(
        return_value={"id": INSTANCE_ID, "sha256": EICAR_SHA256}
    )
    client.submit_sandbox_by_instance_async = MagicMock(return_value="new-task")
    client.get_sandbox_results = MagicMock(return_value=_task(id="new-task"))
    client.get_scan_by_hash = MagicMock(return_value=(None, None))
    client.generate_pdf = MagicMock(return_value=b"%PDF-1.4")
    return c


def _run(c, entity=None, opencti=None, stix_objects=None):
    entity = entity or _stixfile()
    with patch("connector.polyswarm_connector.time.sleep"):
        return c._enrich_file(
            FILE_ID,
            entity,
            opencti or _opencti_file(),
            [entity] if stix_objects is None else stix_objects,
        )


def _bundle_objects(c):
    calls = c.helper.stix2_create_bundle.call_args_list
    return calls[-1].args[0] if calls else []


def _notes(c):
    return [o for o in _bundle_objects(c) if o["type"] == "note"]


def _file_names(c):
    return [
        call.kwargs["file_name"]
        for call in c.helper.api.stix_cyber_observable.add_file.call_args_list
    ]


# -- Gap 1: lookup


class TestLookupFound:
    def test_cape_report_produces_detonation_output(self):
        c = _connector()
        assert _run(c) is None

        # Nothing was submitted anywhere
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()
        c.polyswarm_client.submit_sandbox_async.assert_not_called()
        c.polyswarm_client.get_latest_sandbox_task.assert_called_once_with(
            EICAR_SHA256, "cape"
        )

        objects = _bundle_objects(c)
        notes = _notes(c)
        assert any(
            n["abstract"] == "PolySwarm Cape Sandbox Analysis"
            and n["object_refs"] == [FILE_ID]
            for n in notes
        )
        file_obj = [o for o in objects if o["id"] == FILE_ID]
        assert len(file_obj) == 1 and "x_opencti_score" in file_obj[0]

        names = _file_names(c)
        assert f"Sandbox_cape_{EICAR_SHA256[:16]}.json" in names
        assert "PolySwarm_Sandbox_cape_eicar.com.pdf" in names
        c.polyswarm_client.generate_pdf.assert_called_once_with(
            _task()["id"], "sandbox"
        )
        for call in c.helper.api.stix_cyber_observable.add_file.call_args_list:
            assert call.kwargs["id"] == FILE_ID

    def test_two_providers(self):
        c = _connector(
            latest={"cape": _task(), "triage": _task("triage")},
            sandbox_provider="both",
        )
        assert _run(c) is None
        abstracts = {n["abstract"] for n in _notes(c)}
        assert "PolySwarm Cape Sandbox Analysis" in abstracts
        assert "PolySwarm Triage Sandbox Analysis" in abstracts
        assert c.polyswarm_client.get_latest_sandbox_task.call_count == 2

    def test_one_of_two_providers_found(self):
        c = _connector(latest={"triage": _task("triage")}, sandbox_provider="both")
        assert _run(c) is None
        abstracts = {n["abstract"] for n in _notes(c)}
        assert "PolySwarm Triage Sandbox Analysis" in abstracts
        assert "PolySwarm Cape Sandbox Analysis" not in abstracts

    def test_sha1_only_is_resolved_through_search(self):
        c = _connector()
        entity = _stixfile({"SHA-1": "a" * 40})
        assert _run(c, entity) is None
        c.polyswarm_client.find_instance_by_hash.assert_called_once_with("a" * 40)
        c.polyswarm_client.get_latest_sandbox_task.assert_called_once_with(
            EICAR_SHA256, "cape"
        )

    @pytest.mark.parametrize("algo", ["SHA1", "sha-1", "SHA-1"])
    def test_sha1_spellings(self, algo):
        c = _connector()
        assert _run(c, _stixfile({algo: "a" * 40})) is None
        c.polyswarm_client.find_instance_by_hash.assert_called_once_with("a" * 40)

    def test_hash_list_shape(self):
        c = _connector()
        entity = _stixfile(
            [
                {"algorithm": "SHA-256", "hash": EICAR_SHA256},
                {"algorithm": "MD5", "hash": "b" * 32},
            ]
        )
        assert _run(c, entity) is None
        c.polyswarm_client.get_latest_sandbox_task.assert_called_once_with(
            EICAR_SHA256, "cape"
        )

    def test_llm_report_fired_only_when_enabled(self):
        c = _connector()
        _run(c)
        c.polyswarm_client.create_llm_report.assert_not_called()

        c = _connector(llm_report_enabled=True)
        c.polyswarm_client.create_llm_report = MagicMock(return_value=None)
        _run(c)
        c.polyswarm_client.create_llm_report.assert_called_once_with(
            sandbox_task_id=_task()["id"], provider="cape"
        )

    def test_routes_from_process_message(self):
        c = _connector()
        c._enrich_stixfile = MagicMock(return_value=None)
        c.artifact_handler.download_artifact = MagicMock()
        result = c._process_message(
            {
                "enrichment_entity": _opencti_file(),
                "stix_entity": _stixfile(),
                "stix_objects": [],
                "entity_id": "x",
            }
        )
        assert "success" in result
        c._enrich_stixfile.assert_called_once()
        c.artifact_handler.download_artifact.assert_not_called()

    def test_stixfile_out_of_scope_without_setting(self):
        c = _connector()
        c.helper.connect_scope = "Artifact,Url"
        c._enrich_stixfile = MagicMock()
        result = c._process_message(
            {"enrichment_entity": _opencti_file(), "stix_objects": [], "entity_id": "x"}
        )
        assert "not in scope" in result.lower()
        c._enrich_stixfile.assert_not_called()


class TestLookupAge:
    @pytest.mark.parametrize(
        "max_age, age_days, usable",
        [
            (0, 4000, True),  # 0 = any age
            (30, 5, True),
            (30, 31, False),
            (30, 29, True),
        ],
    )
    def test_age_limit(self, max_age, age_days, usable):
        c = _connector(
            latest={"cape": _task(created=_days_ago(age_days))},
            sandbox_lookup_max_age_days=max_age,
        )
        assert _run(c) is None
        found = any(
            n["abstract"] == "PolySwarm Cape Sandbox Analysis" for n in _notes(c)
        )
        assert found is usable
        if not usable:
            assert any(
                "older than 30 days" in n["content"]
                for n in _notes(c)
                if "No PolySwarm Sandbox Report" in n["abstract"]
            ) or not _notes(c)

    def test_unparseable_created_with_limit_is_missing(self):
        c = _connector(
            latest={"cape": _task(created="not a date")},
            sandbox_lookup_max_age_days=30,
        )
        _run(c)
        assert not any("Cape Sandbox Analysis" in n["abstract"] for n in _notes(c))

    def test_naive_and_z_timestamps(self):
        recent = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        for stamp in (recent, _days_ago(1).replace("+00:00", "Z")):
            c = _connector(
                latest={"cape": _task(created=stamp)}, sandbox_lookup_max_age_days=30
            )
            _run(c)
            assert any("Cape Sandbox Analysis" in n["abstract"] for n in _notes(c))


class TestLookupMissing:
    def test_no_report_attaches_note_and_sends_nothing(self):
        c = _connector(latest={})
        assert _run(c) is None
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()
        c.polyswarm_client.find_instance_by_hash.assert_not_called()
        notes = _notes(c)
        assert len(notes) == 1
        text = notes[0]["content"]
        assert "no usable sandbox report" in text
        assert "POLYSWARM_SANDBOX_DETONATE_BY_HASH=true" in text
        assert "spends sandbox credits" in text
        assert notes[0]["object_refs"] == [FILE_ID]

    def test_note_omits_setting_hint_when_already_on_and_not_held(self):
        c = _connector(latest={}, sandbox_detonate_by_hash=True)
        c.polyswarm_client.find_instance_by_hash = MagicMock(return_value=None)
        assert _run(c) is None
        text = _notes(c)[0]["content"]
        assert "does not hold the sample" in text
        assert "Nothing was uploaded" in text

    def test_failed_or_pending_report_is_not_usable(self):
        for status in ("FAILED", "PENDING", "TIMED OUT"):
            c = _connector(latest={"cape": _task(status=status)})
            _run(c)
            assert not any("Cape Sandbox Analysis" in n["abstract"] for n in _notes(c))
            assert any(
                "No PolySwarm Sandbox Report" in n["abstract"] for n in _notes(c)
            )

    def test_unknown_hash_for_sha1_gives_note(self):
        c = _connector(latest={})
        c.polyswarm_client.find_instance_by_hash = MagicMock(return_value=None)
        assert _run(c, _stixfile({"MD5": "c" * 32})) is None
        c.polyswarm_client.get_latest_sandbox_task.assert_not_called()
        content = _notes(c)[0]["content"]
        assert "no record of this hash" in content
        assert "'acme-private'" in content

    def test_no_hash_gives_error_note(self):
        c = _connector()
        c._send_error_note = MagicMock()
        result = _run(c, _stixfile({}))
        assert result["status"] == "error"
        assert c._send_error_note.call_args.args[1] == "No Hash"
        c.polyswarm_client.get_latest_sandbox_task.assert_not_called()


class TestLookupGuards:
    def test_sandbox_disabled(self):
        c = _connector(sandbox_enabled=False)
        c._send_error_note = MagicMock()
        result = _run(c)
        assert result["status"] == "error"
        assert c._send_error_note.call_args.args[1] == "Sandbox Disabled"
        c.polyswarm_client.get_latest_sandbox_task.assert_not_called()

    def test_tlp_skip(self):
        c = _connector()
        c.max_tlp = "TLP:AMBER"
        opencti = _opencti_file(
            objectMarking=[{"definition_type": "TLP", "definition": "TLP:RED"}]
        )
        result = _run(c, opencti=opencti)
        assert result["status"] == "skipped"
        c.polyswarm_client.get_latest_sandbox_task.assert_not_called()

    def test_lookup_works_in_public_community(self):
        """A lookup sends only a hash, so the upload guard does not apply."""
        c = _connector(community="default", allow_public_community=False)
        assert _run(c) is None
        assert any("Cape Sandbox Analysis" in n["abstract"] for n in _notes(c))

    def test_api_error_propagates_for_error_note(self):
        c = _connector()
        c.polyswarm_client.get_latest_sandbox_task = MagicMock(
            side_effect=PolySwarmAPIError("API Access Denied", "no plan")
        )
        with pytest.raises(PolySwarmAPIError):
            _run(c)

    def test_enrich_context_cleared(self):
        c = _connector()
        _run(c)
        assert c._enrich_ctx == ""


# -- Gap 2: detonate by hash


class TestDetonateByHash:
    def test_off_by_default_never_detonates(self):
        c = _connector(latest={})
        _run(c)
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()
        c.polyswarm_client.find_instance_by_hash.assert_not_called()

    def test_report_exists_means_no_detonation(self):
        c = _connector(sandbox_detonate_by_hash=True)
        _run(c)
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()

    def test_detonates_held_sample(self):
        c = _connector(latest={}, sandbox_detonate_by_hash=True)
        assert _run(c) is None
        c.polyswarm_client.find_instance_by_hash.assert_called_once_with(EICAR_SHA256)
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_called_once_with(
            INSTANCE_ID, "cape", "win-10-build-19041", True
        )
        # No upload from OpenCTI
        c.polyswarm_client.submit_sandbox_async.assert_not_called()
        c.polyswarm_client.submit_file_async.assert_not_called()
        c.artifact_handler.download_artifact.assert_not_called()
        c.polyswarm_client.get_sandbox_results.assert_called_with("new-task")
        assert any("Cape Sandbox Analysis" in n["abstract"] for n in _notes(c))
        assert f"Sandbox_cape_{EICAR_SHA256[:16]}.json" in _file_names(c)
        c.polyswarm_client.generate_pdf.assert_called_once_with("new-task", "sandbox")

    def test_network_setting_is_passed(self):
        c = _connector(
            latest={}, sandbox_detonate_by_hash=True, sandbox_network_enabled=False
        )
        _run(c)
        assert (
            c.polyswarm_client.submit_sandbox_by_instance_async.call_args.args[3]
            is False
        )

    def test_only_missing_providers_are_detonated(self):
        c = _connector(
            latest={"triage": _task("triage")},
            sandbox_provider="both",
            sandbox_detonate_by_hash=True,
        )
        assert _run(c) is None
        calls = c.polyswarm_client.submit_sandbox_by_instance_async.call_args_list
        assert [call.args[1] for call in calls] == ["cape"]
        abstracts = {n["abstract"] for n in _notes(c)}
        assert "PolySwarm Cape Sandbox Analysis" in abstracts
        assert "PolySwarm Triage Sandbox Analysis" in abstracts

    def test_stale_report_triggers_detonation(self):
        c = _connector(
            latest={"cape": _task(created=_days_ago(90))},
            sandbox_lookup_max_age_days=30,
            sandbox_detonate_by_hash=True,
        )
        _run(c)
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_called_once()

    def test_sample_not_held(self):
        c = _connector(latest={}, sandbox_detonate_by_hash=True)
        c.polyswarm_client.find_instance_by_hash = MagicMock(return_value=None)
        assert _run(c) is None
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()
        text = _notes(c)[0]["content"]
        assert "does not hold the sample" in text

    @pytest.mark.parametrize("community", ["default", "public", "mainnet1", ""])
    def test_public_community_guard(self, community):
        c = _connector(
            latest={},
            sandbox_detonate_by_hash=True,
            community=community,
            allow_public_community=False,
        )
        c._send_error_note = MagicMock()
        result = _run(c)
        assert result["status"] == "error"
        assert c._send_error_note.call_args.args[1] == (
            "Detonation Refused: Public Community"
        )
        c.polyswarm_client.find_instance_by_hash.assert_not_called()
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()

    def test_public_community_with_opt_in(self):
        c = _connector(
            latest={},
            sandbox_detonate_by_hash=True,
            community="default",
            allow_public_community=True,
        )
        assert _run(c) is None
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_called_once()

    def test_guard_refusal_keeps_found_reports(self):
        c = _connector(
            latest={"triage": _task("triage")},
            sandbox_provider="both",
            sandbox_detonate_by_hash=True,
            community="default",
            allow_public_community=False,
        )
        assert _run(c) is None
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()
        assert any("Triage Sandbox Analysis" in n["abstract"] for n in _notes(c))

    def test_submit_failure(self):
        c = _connector(latest={}, sandbox_detonate_by_hash=True)
        c.polyswarm_client.submit_sandbox_by_instance_async = MagicMock(
            return_value=None
        )
        c._send_error_note = MagicMock()
        result = _run(c)
        assert result["status"] == "error"
        assert c._send_error_note.call_args.args[1] == "Sandbox Submission Failed"

    def test_submit_failure_keeps_found_reports(self):
        c = _connector(
            latest={"triage": _task("triage")},
            sandbox_provider="both",
            sandbox_detonate_by_hash=True,
        )
        c.polyswarm_client.submit_sandbox_by_instance_async = MagicMock(
            return_value=None
        )
        assert _run(c) is None
        assert any("Triage Sandbox Analysis" in n["abstract"] for n in _notes(c))

    def test_failed_detonation_gives_failure_note(self):
        c = _connector(latest={}, sandbox_detonate_by_hash=True)
        c.polyswarm_client.get_sandbox_results = MagicMock(
            return_value=_task(id="new-task", status="FAILED")
        )
        assert _run(c) is None
        c.polyswarm_client.generate_pdf.assert_not_called()
        assert _notes(c)

    def test_one_provider_times_out_other_succeeds(self):
        c = _connector(
            latest={},
            sandbox_provider="both",
            sandbox_detonate_by_hash=True,
        )
        c.polyswarm_client.submit_sandbox_by_instance_async = MagicMock(
            side_effect=lambda sha, prov, *a, **k: f"task-{prov}"
        )
        c._poll_sandbox_results = MagicMock(
            return_value={"cape": _task(id="task-cape"), "triage": None}
        )
        c._send_error_note = MagicMock()
        assert _run(c) is None
        titles = [call.args[1] for call in c._send_error_note.call_args_list]
        assert titles == ["TRIAGE Sandbox Timeout"]
        abstracts = {n["abstract"] for n in _notes(c)}
        assert "PolySwarm Cape Sandbox Analysis" in abstracts
        # The timeout is reported once (the note above), never as a report
        assert not any("TRIAGE" in a and "TIMED OUT" in a for a in abstracts)
        assert not any("Sandbox_triage" in n for n in _file_names(c))

    def test_all_providers_time_out_returns_error(self):
        c = _connector(
            latest={},
            sandbox_provider="both",
            sandbox_detonate_by_hash=True,
            sandbox_timeout=0,
        )
        c._send_error_note = MagicMock()
        result = _run(c)
        assert result["status"] == "error"
        assert "timeout" in result["error"]
        titles = sorted(call.args[1] for call in c._send_error_note.call_args_list)
        assert titles == ["CAPE Sandbox Timeout", "TRIAGE Sandbox Timeout"]
        c.helper.stix2_create_bundle.assert_not_called()

    @pytest.mark.parametrize(
        "status", ["TIMEDOUT", "TIMED OUT WITH QUOTA REIMBURSEMENT", "timed out"]
    )
    def test_provider_reported_timeout_variants_return_error(self, status):
        c = _connector(
            latest={}, sandbox_provider="both", sandbox_detonate_by_hash=True
        )
        c.polyswarm_client.submit_sandbox_by_instance_async = MagicMock(
            side_effect=lambda sha, prov, *a, **k: f"task-{prov}"
        )
        c._poll_sandbox_results = MagicMock(
            return_value={
                "cape": _task(id="task-cape", status=status),
                "triage": _task("triage", id="task-triage", status=status),
            }
        )
        result = _run(c)
        assert result["status"] == "error"
        assert "timeout" in result["error"]
        # the provider's own timeout explanation still reaches the analyst
        assert _notes(c)
        c.polyswarm_client.generate_pdf.assert_not_called()

    def test_timeout_plus_real_failure_keeps_failure_path(self):
        c = _connector(
            latest={}, sandbox_provider="both", sandbox_detonate_by_hash=True
        )
        c.polyswarm_client.submit_sandbox_by_instance_async = MagicMock(
            side_effect=lambda sha, prov, *a, **k: f"task-{prov}"
        )
        c._poll_sandbox_results = MagicMock(
            return_value={
                "cape": _task(id="task-cape", status="FAILED"),
                "triage": None,
            }
        )
        c._send_error_note = MagicMock()
        assert _run(c) is None
        assert not any("Sandbox_triage" in n for n in _file_names(c))

    def test_all_time_out_forwards_original_bundle(self):
        c = _connector(latest={}, sandbox_detonate_by_hash=True, sandbox_timeout=0)
        c._send_error_note = MagicMock()
        c._send_original_bundle = MagicMock()
        entity = _stixfile()
        with patch("connector.polyswarm_connector.time.sleep"):
            out = c._process_message(
                {
                    "enrichment_entity": _opencti_file(),
                    "stix_entity": entity,
                    "stix_objects": [entity],
                    "entity_id": FILE_ID,
                }
            )
        assert json.loads(out)["status"] == "error"
        c._send_original_bundle.assert_called_once()

    def test_polling_uses_configured_timeouts(self):
        c = _connector(
            latest={},
            sandbox_detonate_by_hash=True,
            poll_interval=7,
            sandbox_timeout=99,
        )
        c._phase_poll_sandboxes = MagicMock(return_value={"cape": None})
        _run(c)
        assert c._phase_poll_sandboxes.call_args.args[1] == {"cape": "new-task"}
        assert c._phase_poll_sandboxes.call_args.args[2:4] == (7, 99)


class TestLookupFailureNeverDetonates:
    """A failed lookup is not "no report", and a running task is not missing."""

    def test_failed_lookup_does_not_detonate(self):
        c = _connector(latest={"cape": None}, sandbox_detonate_by_hash=True)
        c._send_error_note = MagicMock()
        result = _run(c)
        assert result["status"] == "error"
        assert "lookup failed" in result["error"]
        c.polyswarm_client.find_instance_by_hash.assert_not_called()
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()
        titles = [call.args[1] for call in c._send_error_note.call_args_list]
        assert titles == ["Sandbox Lookup Failed"]
        assert "nothing was detonated" in c._send_error_note.call_args.args[2]

    def test_sdk_server_error_does_not_detonate(self):
        """The real client turns an SDK 503 into a failed lookup, not a miss."""
        c = _connector(sandbox_detonate_by_hash=True)
        real = _client()
        real.api.sandbox_task_latest = MagicMock(
            side_effect=ps_exceptions.RequestException(
                MagicMock(status_code=503), "Return code: 503"
            )
        )
        c.polyswarm_client.get_latest_sandbox_task = real.get_latest_sandbox_task
        c._send_error_note = MagicMock()
        result = _run(c)
        assert result["status"] == "error"
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()

    def test_not_found_still_detonates(self):
        c = _connector(sandbox_detonate_by_hash=True)
        real = _client()
        real.api.sandbox_task_latest = MagicMock(
            side_effect=ps_exceptions.NotFoundException(
                MagicMock(status_code=404), "No tasks found."
            )
        )
        c.polyswarm_client.get_latest_sandbox_task = real.get_latest_sandbox_task
        assert _run(c) is None
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_called_once()

    def test_failed_lookup_without_detonation_is_not_no_report(self):
        c = _connector(latest={"cape": None})
        c._send_error_note = MagicMock()
        result = _run(c)
        assert result["status"] == "error"
        assert not any(
            "No PolySwarm Sandbox Report" in n["abstract"] for n in _notes(c)
        )
        assert c._send_error_note.call_args.args[1] == "Sandbox Lookup Failed"

    def test_one_provider_failed_other_missing_detonates_only_missing(self):
        c = _connector(
            latest={"cape": None},
            sandbox_provider="both",
            sandbox_detonate_by_hash=True,
        )
        c._send_error_note = MagicMock()
        assert _run(c) is None
        calls = c.polyswarm_client.submit_sandbox_by_instance_async.call_args_list
        assert [call.args[1] for call in calls] == ["triage"]
        titles = [call.args[1] for call in c._send_error_note.call_args_list]
        assert "Sandbox Lookup Failed" in titles

    def test_failed_lookup_keeps_found_reports(self):
        c = _connector(
            latest={"cape": None, "triage": _task("triage")},
            sandbox_provider="both",
            sandbox_detonate_by_hash=True,
        )
        c._send_error_note = MagicMock()
        assert _run(c) is None
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()
        assert any("Triage Sandbox Analysis" in n["abstract"] for n in _notes(c))

    @pytest.mark.parametrize("status", ["PENDING", "RUNNING", "STARTED"])
    def test_running_task_is_polled_not_detonated_again(self, status):
        c = _connector(
            latest={"cape": _task(id="running-task", status=status)},
            sandbox_detonate_by_hash=True,
        )
        c.polyswarm_client.get_sandbox_results = MagicMock(
            return_value=_task(id="running-task")
        )
        assert _run(c) is None
        c.polyswarm_client.find_instance_by_hash.assert_not_called()
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_not_called()
        c.polyswarm_client.get_sandbox_results.assert_called_with("running-task")
        assert any("Cape Sandbox Analysis" in n["abstract"] for n in _notes(c))

    def test_running_plus_missing_polls_both(self):
        c = _connector(
            latest={"cape": _task(id="running-task", status="PENDING")},
            sandbox_provider="both",
            sandbox_detonate_by_hash=True,
        )
        c._phase_poll_sandboxes = MagicMock(return_value={})
        _run(c)
        calls = c.polyswarm_client.submit_sandbox_by_instance_async.call_args_list
        assert [call.args[1] for call in calls] == ["triage"]
        assert c._phase_poll_sandboxes.call_args.args[1] == {
            "triage": "new-task",
            "cape": "running-task",
        }

    def test_stale_running_task_is_missing(self):
        c = _connector(
            latest={"cape": _task(status="PENDING", created=_days_ago(90))},
            sandbox_lookup_max_age_days=30,
            sandbox_detonate_by_hash=True,
        )
        _run(c)
        c.polyswarm_client.submit_sandbox_by_instance_async.assert_called_once()

    def test_running_task_with_detonation_off_gives_no_report_note(self):
        c = _connector(latest={"cape": _task(status="PENDING")})
        assert _run(c) is None
        c.polyswarm_client.get_sandbox_results.assert_not_called()
        assert any("No PolySwarm Sandbox Report" in n["abstract"] for n in _notes(c))

    def test_artifact_reuse_failed_lookup_uploads(self):
        c = _connector(latest={"cape": None}, sandbox_reuse_report=True)
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        entity = {
            "type": "artifact",
            "spec_version": "2.1",
            "id": ARTIFACT_ID,
            "hashes": {"SHA-256": EICAR_SHA256},
        }
        with patch("connector.polyswarm_connector.time.sleep"):
            c._enrich_file(
                ARTIFACT_ID,
                entity,
                {"entity_type": "Artifact", "standard_id": ARTIFACT_ID},
                [entity],
            )
        c.artifact_handler.download_artifact.assert_called_once()


# -- Artifact: reuse an existing report before uploading


def _scan():
    return {
        "id": INSTANCE_ID,
        "failed": False,
        "window_closed": True,
        "polyscore": 0.9,
        "sha256": EICAR_SHA256,
        "assertions": [],
        "permalink": "https://polyswarm.network/scan/results/x",
        "filename": "eicar.com",
        "first_seen": "2026-06-23T00:00:00",
        "last_seen": "2026-06-23T00:00:00",
        "last_scanned": "2026-06-23T00:00:00",
        "detections": {"benign": 0, "malicious": 0, "total": 0},
        "metadata": [],
        "extended_type": "x",
        "mimetype": "x",
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "size": 68,
        "community": "default",
        "created": "2026-06-23T00:00:00",
        "country": None,
        "type": "FILE",
        "result": None,
        "state": "x",
        "votes": [],
        "expire_at": None,
    }


class TestArtifactReuse:
    def _artifact(self):
        return (
            {
                "type": "artifact",
                "spec_version": "2.1",
                "id": ARTIFACT_ID,
                "hashes": {"SHA-256": EICAR_SHA256},
            },
            {"entity_type": "Artifact", "standard_id": ARTIFACT_ID},
        )

    def _run_artifact(self, c):
        entity, opencti = self._artifact()
        with patch("connector.polyswarm_connector.time.sleep"):
            return c._enrich_file(ARTIFACT_ID, entity, opencti, [entity])

    def test_reuse_skips_upload(self):
        c = _connector(sandbox_reuse_report=True)
        c.polyswarm_client.get_scan_by_hash = MagicMock(
            return_value=(INSTANCE_ID, _scan())
        )
        assert self._run_artifact(c) is None
        c.artifact_handler.download_artifact.assert_not_called()
        c.polyswarm_client.submit_file_async.assert_not_called()
        c.polyswarm_client.submit_sandbox_async.assert_not_called()
        assert any("Cape Sandbox Analysis" in n["abstract"] for n in _notes(c))

    def test_reuse_works_in_public_community(self):
        c = _connector(
            sandbox_reuse_report=True, community="default", allow_public_community=False
        )
        c.polyswarm_client.get_scan_by_hash = MagicMock(
            return_value=(INSTANCE_ID, _scan())
        )
        assert self._run_artifact(c) is None
        c.artifact_handler.download_artifact.assert_not_called()
        assert any("Cape Sandbox Analysis" in n["abstract"] for n in _notes(c))

    def test_reports_without_finished_scan_upload(self):
        c = _connector(sandbox_reuse_report=True)
        c.polyswarm_client.get_scan_by_hash = MagicMock(return_value=(None, None))
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        result = self._run_artifact(c)
        assert result["status"] == "error"
        c.artifact_handler.download_artifact.assert_called_once()

    def test_failed_scan_uploads(self):
        c = _connector(sandbox_reuse_report=True)
        c.polyswarm_client.get_scan_by_hash = MagicMock(
            return_value=(INSTANCE_ID, {**_scan(), "failed": True})
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        result = self._run_artifact(c)
        assert result["status"] == "error"
        c.artifact_handler.download_artifact.assert_called_once()

    def test_reuse_brings_the_existing_scan(self):
        c = _connector(sandbox_reuse_report=True)
        scan = _scan()
        c.polyswarm_client.get_scan_by_hash = MagicMock(
            return_value=(INSTANCE_ID, scan)
        )
        assert self._run_artifact(c) is None
        names = _file_names(c)
        assert f"Scan_result_{EICAR_SHA256[:16]}.json" in names
        assert "PolySwarm_Scan_" in " ".join(names)
        c.polyswarm_client.generate_pdf.assert_any_call(INSTANCE_ID, "scan")

    def test_partial_coverage_uploads(self):
        c = _connector(
            latest={"cape": _task()}, sandbox_reuse_report=True, sandbox_provider="both"
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        result = self._run_artifact(c)
        assert result["status"] == "error"
        c.artifact_handler.download_artifact.assert_called_once()

    def test_no_report_uploads(self):
        c = _connector(latest={}, sandbox_reuse_report=True)
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        self._run_artifact(c)
        c.artifact_handler.download_artifact.assert_called_once()

    def test_stale_report_uploads(self):
        c = _connector(
            latest={"cape": _task(created=_days_ago(90))},
            sandbox_reuse_report=True,
            sandbox_lookup_max_age_days=30,
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        self._run_artifact(c)
        c.artifact_handler.download_artifact.assert_called_once()

    def test_reuse_off_never_looks_up(self):
        c = _connector(sandbox_reuse_report=False)
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        self._run_artifact(c)
        c.polyswarm_client.get_latest_sandbox_task.assert_not_called()
        c.artifact_handler.download_artifact.assert_called_once()

    def test_sandbox_off_never_looks_up(self):
        c = _connector(sandbox_reuse_report=True, sandbox_enabled=False)
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        self._run_artifact(c)
        c.polyswarm_client.get_latest_sandbox_task.assert_not_called()

    def test_lookup_error_falls_back_to_upload(self):
        c = _connector(sandbox_reuse_report=True)
        c.polyswarm_client.get_latest_sandbox_task = MagicMock(
            side_effect=PolySwarmAPIError("API Access Denied", "no plan")
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        self._run_artifact(c)
        c.artifact_handler.download_artifact.assert_called_once()

    def test_artifact_without_sha256_uploads(self):
        c = _connector(sandbox_reuse_report=True)
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        entity, opencti = self._artifact()
        entity["hashes"] = {}
        with patch("connector.polyswarm_connector.time.sleep"):
            c._enrich_file(ARTIFACT_ID, entity, opencti, [entity])
        c.polyswarm_client.get_latest_sandbox_task.assert_not_called()

    def test_quota_exhausted_lookup_ends_enrichment_without_upload(self):
        c = _connector(sandbox_reuse_report=True)
        c.polyswarm_client.get_latest_sandbox_task = MagicMock(
            side_effect=PolySwarmAPIError(
                f"{PolySwarmAPIError.QUOTA_CATEGORY} (sandbox lookup)", "429"
            )
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        with pytest.raises(PolySwarmAPIError) as exc:
            self._run_artifact(c)
        assert exc.value.is_quota_exhausted
        c.artifact_handler.download_artifact.assert_not_called()
        c.polyswarm_client.submit_file_async.assert_not_called()

    def test_quota_exhausted_lookup_reaches_the_quota_note(self):
        c = _connector(sandbox_reuse_report=True)
        c.polyswarm_client.get_latest_sandbox_task = MagicMock(
            side_effect=PolySwarmAPIError(
                f"{PolySwarmAPIError.QUOTA_CATEGORY} (sandbox lookup)", "429"
            )
        )
        c.artifact_handler.download_artifact = MagicMock(return_value=(None, "stop"))
        c._send_error_note = MagicMock()
        c._send_original_bundle = MagicMock()
        entity, opencti = self._artifact()
        result = c._process_message(
            {
                "enrichment_entity": opencti,
                "stix_entity": entity,
                "stix_objects": [entity],
                "entity_id": ARTIFACT_ID,
            }
        )
        assert json.loads(result)["status"] == "error"
        assert c._send_error_note.call_args.args[1].startswith(
            PolySwarmAPIError.QUOTA_CATEGORY
        )
        c.artifact_handler.download_artifact.assert_not_called()


# -- Client


def _client():
    return PolySwarmClient(
        api_key="test-key",
        api_url="https://api.polyswarm.network",
        community="acme-private",
        timeout=10,
        helper=MagicMock(),
    )


class _Resp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body

    def raise_for_status(self):
        return None


class TestClientLookup:
    def test_latest_real_sdk_request(self):
        c = _client()
        task = _task()
        seen = []

        def fake_request(**kwargs):
            seen.append(kwargs)
            return _Resp(200, {"result": task, "status": "OK"})

        with patch.object(c.api.session, "request", side_effect=fake_request):
            got = c.get_latest_sandbox_task(EICAR_SHA256, "cape")
        assert got["id"] == task["id"]
        assert seen[0]["method"] == "GET"
        assert seen[0]["url"].endswith("/sandbox/sandboxtask/latest")
        assert seen[0]["params"]["sha256"] == EICAR_SHA256
        assert seen[0]["params"]["sandbox"] == "cape"
        assert seen[0]["params"]["community"] == "acme-private"

    def test_latest_404_is_empty_and_not_retried(self):
        c = _client()
        calls = []

        def fake_request(**kwargs):
            calls.append(kwargs)
            return _Resp(404, {"result": "No tasks found.", "status": "ERROR"})

        with patch.object(c.api.session, "request", side_effect=fake_request):
            assert c.get_latest_sandbox_task("0" * 64, "cape") == {}
        assert len(calls) == 1

    def test_latest_server_error_is_none_not_empty(self):
        """A 5xx is a failed lookup (None), never a confirmed miss ({})."""
        c = _client()

        def fake_request(**kwargs):
            return _Resp(503, {"result": "unavailable", "status": "ERROR"})

        with patch.object(c.api.session, "request", side_effect=fake_request):
            assert c.get_latest_sandbox_task(EICAR_SHA256, "cape") is None

    def test_latest_breaker_open_is_none(self):
        c = _client()
        for _ in range(c._breaker.failure_threshold):
            c._breaker.record_failure()
        c.api.sandbox_task_latest = MagicMock()
        assert c.get_latest_sandbox_task(EICAR_SHA256, "cape") is None
        c.api.sandbox_task_latest.assert_not_called()

    def test_latest_quota_error_raises(self):
        c = _client()
        err = ps_exceptions.RequestException(MagicMock(status_code=402), "HTTP 402")
        c.api.sandbox_task_latest = MagicMock(side_effect=err)
        with pytest.raises(PolySwarmAPIError):
            c.get_latest_sandbox_task(EICAR_SHA256, "cape")

    def test_latest_unexpected_error_is_none(self):
        c = _client()
        c.api.sandbox_task_latest = MagicMock(side_effect=ValueError("boom"))
        assert c.get_latest_sandbox_task(EICAR_SHA256, "cape") is None

    def test_find_instance(self):
        c = _client()
        inst = MagicMock(json={"id": INSTANCE_ID, "sha256": EICAR_SHA256})
        c.api.search = MagicMock(return_value=iter([inst]))
        assert c.find_instance_by_hash(EICAR_SHA256)["id"] == INSTANCE_ID
        c.api.search.assert_called_once_with(EICAR_SHA256)

    @pytest.mark.parametrize(
        "exc", [ps_exceptions.NoResultsException, ps_exceptions.NotFoundException]
    )
    def test_find_instance_not_held(self, exc):
        c = _client()
        c.api.search = MagicMock(side_effect=exc(MagicMock(), "none"))
        assert c.find_instance_by_hash("0" * 64) is None

    def test_find_instance_empty_list(self):
        c = _client()
        c.api.search = MagicMock(return_value=iter([]))
        assert c.find_instance_by_hash("0" * 64) is None

    def test_find_instance_unexpected_error(self):
        c = _client()
        c.api.search = MagicMock(side_effect=ValueError("boom"))
        assert c.find_instance_by_hash("0" * 64) is None

    def test_get_scan_by_hash(self):
        c = _client()
        c.find_instance_by_hash = MagicMock(return_value={"id": INSTANCE_ID})
        c.get_scan_results = MagicMock(return_value={"id": INSTANCE_ID})
        assert c.get_scan_by_hash(EICAR_SHA256) == (INSTANCE_ID, {"id": INSTANCE_ID})
        c.get_scan_results = MagicMock(return_value=None)
        assert c.get_scan_by_hash(EICAR_SHA256) == (None, None)
        c.find_instance_by_hash = MagicMock(return_value=None)
        assert c.get_scan_by_hash(EICAR_SHA256) == (None, None)


class TestClientDetonateByInstance:
    def test_sdk_call(self):
        c = _client()
        task = resources.SandboxTask(_fixture("sandbox_task_latest_eicar_cape.json"))
        c.api.sandbox = MagicMock(return_value=task)
        got = c.submit_sandbox_by_instance_async(
            INSTANCE_ID, "cape", "win-10-build-19041", False
        )
        assert got == task.id
        c.api.sandbox.assert_called_once_with(
            INSTANCE_ID, "cape", "win-10-build-19041", False
        )

    def test_failure_returns_none(self):
        c = _client()
        c.api.sandbox = MagicMock(side_effect=ValueError("boom"))
        assert c.submit_sandbox_by_instance_async(INSTANCE_ID, "cape", "vm") is None

    def test_no_task_returns_none(self):
        c = _client()
        c.api.sandbox = MagicMock(return_value=None)
        assert c.submit_sandbox_by_instance_async(INSTANCE_ID, "cape", "vm") is None

    def test_quota_error_raises(self):
        c = _client()
        err = ps_exceptions.RequestException(MagicMock(status_code=402), "HTTP 402")
        c.api.sandbox = MagicMock(side_effect=err)
        with pytest.raises(PolySwarmAPIError):
            c.submit_sandbox_by_instance_async(INSTANCE_ID, "cape", "vm")


# -- Settings


def _settings(monkeypatch, **env):
    settings = pytest.importorskip(
        "connector.models.configs.settings", reason="connectors_sdk unavailable"
    )
    monkeypatch.setenv("OPENCTI_URL", "http://localhost:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
    monkeypatch.setenv("CONNECTOR_ID", "00000000-0000-0000-0000-000000000011")
    monkeypatch.setenv("POLYSWARM_API_KEY", "test-key")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return settings.ConnectorSettings()


class TestSettings:
    def test_defaults(self, monkeypatch):
        ps = _settings(monkeypatch).polyswarm
        assert ps.sandbox_detonate_by_hash is False
        assert ps.sandbox_reuse_report is False
        assert ps.sandbox_lookup_max_age_days == 0

    def test_default_scope_includes_stixfile(self, monkeypatch):
        scope = _settings(monkeypatch).connector.scope
        assert "StixFile" in scope

    def test_from_env(self, monkeypatch):
        ps = _settings(
            monkeypatch,
            POLYSWARM_SANDBOX_DETONATE_BY_HASH="true",
            POLYSWARM_SANDBOX_REUSE_REPORT="true",
            POLYSWARM_SANDBOX_LOOKUP_MAX_AGE_DAYS="45",
        ).polyswarm
        assert ps.sandbox_detonate_by_hash is True
        assert ps.sandbox_reuse_report is True
        assert ps.sandbox_lookup_max_age_days == 45

    def test_negative_age_rejected(self, monkeypatch):
        with pytest.raises(Exception):
            _settings(monkeypatch, POLYSWARM_SANDBOX_LOOKUP_MAX_AGE_DAYS="-1")
