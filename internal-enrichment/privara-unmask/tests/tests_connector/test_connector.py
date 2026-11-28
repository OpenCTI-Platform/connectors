import io
import json
import logging
import time
import zipfile
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, PrivaraUnmaskConnector
from connector.connector import android_package_kind
from privara_unmask_client import UnmaskError, UnmaskTimeout
from pycti import OpenCTIConnectorHelper

API_KEY = "pvu_test1234_s3cr3tvalue-never-log-me"
JOB_ID = "j_p_vArc3o-FeSz_aMwZyOQ-NOamS"
SAMPLE_ID = "artifact--6b6f6f6b-0000-4000-8000-000000000001"
MB = 1024 * 1024


def make_apk() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return buffer.getvalue()


def make_message(tlp="TLP:GREEN", entity_type="Artifact", files=None):
    files = (
        [{"id": "import/Artifact/x/a.apk", "name": "a.apk", "size": 1234}]
        if files is None
        else files
    )
    stix_entity = {"id": SAMPLE_ID, "type": "artifact", "object_marking_refs": []}
    return {
        "event_type": "update",  # a manual / automatic enrichment (a playbook sends none)
        "entity_id": SAMPLE_ID,
        "enrichment_entity": {
            "id": "octi-id",
            "entity_type": entity_type,
            "observable_value": "a.apk",
            "objectMarking": [{"definition_type": "TLP", "definition": tlp}],
            "importFiles": files,
        },
        "stix_entity": stix_entity,
        "stix_objects": [stix_entity],
    }


JOB_LIVE = {
    "job_id": JOB_ID,
    "status": "done",
    "outcome": "live",
    "charge_cents": 2500,
    "finished_at": int(time.time()) - 600,
    "filename": "a.apk",
    "sha256": "ab" * 32,
    "family": {"name": "Octo", "confidence": 0.55},
    "c2": [
        {
            "value": "http://1.2.3.4/x.php",
            "defanged": "hxxp://1.2.3[.]4/x.php",
            "kind": "url",
            "host": "1.2.3.4",
            "port": None,
            "live": True,
            "confidence": 0.89,
            "source": "runtime_traffic",
        }
    ],
    "rejected_candidates": [],
    "web_url": "https://app.tajapps.com/dashboard/unmask/jobs/" + JOB_ID,
}


@pytest.fixture
def helper():
    helper = MagicMock()
    helper.playbook = None
    helper.api.fetch_opencti_file.return_value = make_apk()
    helper.stix2_create_bundle.side_effect = OpenCTIConnectorHelper.stix2_create_bundle
    helper.send_stix2_bundle.return_value = ["bundle"]
    return helper


@pytest.fixture
def client():
    client = MagicMock()
    client.max_file_bytes.return_value = 200 * MB
    client.lookup.return_value = (None, None)
    client.submit_sample.return_value = {
        "batch_id": "b_Q-x_9",
        "jobs": [{"job_id": JOB_ID, "filename": "a.apk", "status": "queued"}],
    }
    client.wait_for_job.return_value = JOB_LIVE
    return client


@pytest.fixture
def connector(connector_env, helper, client):
    return PrivaraUnmaskConnector(
        config=ConnectorSettings(), helper=helper, client=client
    )


def sent_objects(helper):
    assert helper.send_stix2_bundle.called
    return json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]


def notes(helper):
    return [o for o in sent_objects(helper) if o["type"] == "note"]


def test_settings_defaults(connector_env):
    settings = ConnectorSettings()
    assert settings.connector.auto is False
    assert settings.privara_unmask.max_wait == 3600
    assert settings.privara_unmask.max_file_size_mb is None
    assert (
        str(settings.privara_unmask.api_base_url)
        == "https://app.tajapps.com/api/unmask/v1"
    )
    assert API_KEY not in repr(settings)
    assert API_KEY not in str(settings.model_dump())


def test_settings_refuse_plain_http(connector_env, monkeypatch):
    monkeypatch.setenv(
        "PRIVARA_UNMASK_API_BASE_URL", "http://unmask.example/api/unmask/v1"
    )
    with pytest.raises(Exception):
        ConnectorSettings()


def test_live_result(connector, helper, client):
    message = connector.process_message(make_message())
    assert "outcome live" in message and "charged $25.00" in message
    client.lookup.assert_called_once()
    name, content = client.submit_sample.call_args[0][:2]
    assert name == "a.apk" and content.startswith(b"PK")
    assert client.submit_sample.call_args.kwargs["idempotency_key"].startswith(
        "opencti-"
    )
    objects = sent_objects(helper)
    types = [o["type"] for o in objects]
    assert SAMPLE_ID in [o["id"] for o in objects]  # original objects sent back
    assert types.count("indicator") == 1 and "malware" in types and "note" in types
    assert JOB_LIVE["web_url"] in notes(helper)[0]["content"]


def test_existing_finished_job_is_reused(connector, helper, client):
    client.lookup.return_value = (JOB_LIVE, None)
    message = connector.process_message(make_message())
    assert "no new charge" in message
    client.submit_sample.assert_not_called()
    client.wait_for_job.assert_not_called()
    assert "no new charge" in notes(helper)[0]["abstract"]


def test_existing_running_job_is_waited_for(connector, helper, client):
    client.lookup.return_value = ({"job_id": JOB_ID, "status": "running"}, None)
    connector.process_message(make_message())
    client.submit_sample.assert_not_called()
    assert client.wait_for_job.call_args[0][0] == JOB_ID


def test_lookup_outage_falls_back_to_upload(connector, client):
    client.lookup.side_effect = UnmaskError(503, "unavailable", "later")
    connector.process_message(make_message())
    client.submit_sample.assert_called_once()


def test_refused_file(connector, helper, client):
    client.submit_sample.return_value = {
        "batch_id": "b_Q-x_9",
        "jobs": [
            {
                "filename": "a.apk",
                "status": "refused",
                "refused": {"code": "known_clean", "message": "Signed by a vendor."},
            }
        ],
    }
    message = connector.process_message(make_message())
    assert "known_clean" in message
    client.wait_for_job.assert_not_called()
    content = notes(helper)[0]["content"]
    assert "known clean app" in content and "cost nothing" in content


def test_insufficient_balance_pauses_uploads(connector, helper, client):
    client.submit_sample.side_effect = UnmaskError(
        402, "insufficient_balance", "Top up first."
    )
    first = connector.process_message(make_message())
    second = connector.process_message(make_message())
    assert "balance too low" in first and "balance too low" in second
    assert client.submit_sample.call_count == 1  # no retry storm
    assert "dashboard/unmask/wallet" in notes(helper)[0]["content"]


def test_fair_use_reached(connector, helper, client):
    client.submit_sample.side_effect = UnmaskError(
        403, "fair_use_reached", "Limit reached."
    )
    message = connector.process_message(make_message())
    assert "fair-use" in message
    assert notes(helper)


@pytest.mark.parametrize(
    "status,code,expected",
    [
        (401, "invalid_key", "invalid or revoked"),
        (403, "missing_scope", "lacks a scope"),
    ],
)
def test_key_problems_are_work_errors_without_the_key(
    connector, client, status, code, expected
):
    client.submit_sample.side_effect = UnmaskError(status, code, "nope")
    with pytest.raises(ValueError) as err:
        connector.process_message(make_message())
    assert expected in str(err.value)
    assert API_KEY not in str(err.value)


def test_job_not_found_while_polling(connector, client):
    client.wait_for_job.side_effect = UnmaskError(404, "not_found", "No such job.")
    with pytest.raises(ValueError) as err:
        connector.process_message(make_message())
    assert "not found" in str(err.value)


def test_invalid_key_on_lookup(connector, client):
    client.lookup.side_effect = UnmaskError(401, "invalid_key", "bad")
    with pytest.raises(ValueError):
        connector.process_message(make_message())
    client.submit_sample.assert_not_called()


def test_timeout_leaves_a_note(connector, helper, client):
    client.wait_for_job.side_effect = UnmaskTimeout(
        {"job_id": JOB_ID, "status": "running"}, 3600
    )
    message = connector.process_message(make_message())
    assert "still running" in message
    assert JOB_ID in notes(helper)[0]["content"]


def test_not_an_android_package_is_never_sent(connector, helper, client):
    helper.api.fetch_opencti_file.return_value = b"%PDF-1.7 not an apk"
    message = connector.process_message(make_message())
    assert "not an Android package" in message
    client.lookup.assert_not_called()
    client.submit_sample.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_api_size_limit_is_used(connector, helper, client):
    client.max_file_bytes.return_value = 1 * MB
    files = [{"id": "f", "name": "big.apk", "size": 2 * MB}]
    message = connector.process_message(make_message(files=files))
    assert "larger than the size limit (1 MB)" in message
    helper.api.fetch_opencti_file.assert_not_called()


def test_connector_cap_lowers_the_api_limit(connector_env, monkeypatch, helper, client):
    monkeypatch.setenv("PRIVARA_UNMASK_MAX_FILE_SIZE_MB", "5")
    connector = PrivaraUnmaskConnector(
        config=ConnectorSettings(), helper=helper, client=client
    )
    files = [{"id": "f", "name": "big.apk", "size": 6 * MB}]
    message = connector.process_message(make_message(files=files))
    assert "(5 MB)" in message


def test_tlp_above_max_is_skipped(connector, helper, client):
    message = connector.process_message(make_message(tlp="TLP:RED"))
    assert "max TLP" in message
    helper.api.fetch_opencti_file.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


def test_playbook_gets_the_original_bundle_back(connector, helper, client):
    helper.playbook = {"playbook_id": "p"}
    connector.process_message(make_message(files=[]))
    assert [o["id"] for o in sent_objects(helper)] == [SAMPLE_ID]


def test_no_file_attached(connector, helper, client):
    message = connector.process_message(make_message(entity_type="StixFile", files=[]))
    assert "No file attached" in message
    client.submit_sample.assert_not_called()


def test_api_key_never_logged(connector_env, helper, client, caplog):
    caplog.set_level(logging.DEBUG)
    connector = PrivaraUnmaskConnector(
        config=ConnectorSettings(), helper=helper, client=client
    )
    connector.process_message(make_message())
    client.submit_sample.side_effect = UnmaskError(500, "server_error", "boom")
    with pytest.raises(UnmaskError):
        connector.process_message(make_message())
    logged = caplog.text + repr(helper.connector_logger.mock_calls)
    assert API_KEY not in logged


def test_android_package_detection():
    assert android_package_kind(make_apk()) == "apk"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("com.x.apk", make_apk())
    assert android_package_kind(buffer.getvalue()) == "bundle"
    assert android_package_kind(b"MZ\x90\x00") is None


def test_duplicate_submit_answer_reads_the_full_job(connector, helper, client):
    """POST /samples answers a summary (status `done` for a duplicate): the full job is read."""
    client.submit_sample.return_value = {
        "batch_id": "b_Q-x_9",
        "jobs": [
            {
                "job_id": "j_dup-_1",
                "filename": "a.apk",
                "status": "done",
                "duplicate_of": JOB_ID,
            }
        ],
    }
    client.wait_for_job.return_value = dict(JOB_LIVE, job_id="j_dup-_1", charge_cents=0)
    message = connector.process_message(make_message())
    assert client.wait_for_job.call_args[0][0] == "j_dup-_1"
    assert "no new charge" in message
    assert [o for o in sent_objects(helper) if o["type"] == "indicator"]


def test_runs_again_after_a_none_result_with_a_new_key(connector, client):
    earlier = {"job_id": "j_none-_1", "status": "done", "outcome": "none"}
    client.lookup.return_value = (None, earlier)
    connector.process_message(make_message())
    key = client.submit_sample.call_args.kwargs["idempotency_key"]
    assert key.startswith("opencti-") and key.count("-") >= 2
    client.lookup.return_value = (None, None)
    connector.process_message(make_message())
    assert client.submit_sample.call_args.kwargs["idempotency_key"] != key


def test_rate_limited_leaves_a_note_without_pausing(connector, helper, client):
    client.submit_sample.side_effect = UnmaskError(429, "rate_limited", "Slow down.")
    first = connector.process_message(make_message())
    assert "rate limited" in first and "rate limited" in notes(helper)[0]["abstract"]
    client.submit_sample.side_effect = None
    second = connector.process_message(make_message())
    assert "outcome live" in second  # no 10-minute pause after a 429


def test_api_not_enabled_on_submit(connector, client):
    client.submit_sample.side_effect = UnmaskError(404, "not_found", "Not found.")
    with pytest.raises(ValueError) as err:
        connector.process_message(make_message())
    assert "not enabled" in str(err.value)


def test_liveness_and_intel_in_the_note(connector, helper, client):
    entry = dict(
        JOB_LIVE["c2"][0],
        liveness={
            "state": "live",
            "reason": "http_answer",
            "checked_at": 1,
            "explain": "The panel answered HTTP 200.",
        },
        intel={
            "known": True,
            "feeds": ["threatfox"],
            "malware": "Octo",
            "first_seen": "",
        },
    )
    client.wait_for_job.return_value = dict(JOB_LIVE, c2=[entry])
    connector.process_message(make_message())
    content = notes(helper)[0]["content"]
    assert "answered: The panel answered HTTP 200." in content
    assert "threatfox (Octo)" in content
    indicator = [o for o in sent_objects(helper) if o["type"] == "indicator"][0]
    assert "liveness check: answered" in indicator["description"]


def test_playbook_trigger_out_of_scope_gets_the_original_bundle(
    connector, helper, client
):
    """A playbook message has no event_type: a skipped entity's bundle goes back unchanged."""
    message = make_message(entity_type="Url")
    del message["event_type"]
    connector.process_message(message)
    client.submit_sample.assert_not_called()
    assert [o["id"] for o in sent_objects(helper)] == [SAMPLE_ID]
    assert helper.send_stix2_bundle.call_args.kwargs == {
        "cleanup_inconsistent_bundle": True
    }


def test_any_tlp_above_max_is_skipped(connector, helper, client):
    msg = make_message()
    msg["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": "TLP:RED"},
        {"definition_type": "TLP", "definition": "TLP:GREEN"},
    ]
    message = connector.process_message(msg)
    assert "TLP:RED" in message and "max TLP" in message
    helper.api.fetch_opencti_file.assert_not_called()
    client.submit_sample.assert_not_called()


def test_pause_still_collects_existing_jobs(connector, helper, client):
    client.submit_sample.side_effect = UnmaskError(
        402, "insufficient_balance", "Top up first."
    )
    connector.process_message(make_message())
    client.lookup.return_value = (JOB_LIVE, None)
    message = connector.process_message(make_message())
    assert "no new charge" in message
    assert client.submit_sample.call_count == 1
    assert any(o["type"] == "indicator" for o in sent_objects(helper))
