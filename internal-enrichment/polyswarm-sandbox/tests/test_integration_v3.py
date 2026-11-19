"""Hash lookup results flow through the report-depth objects and markings."""

from unittest.mock import MagicMock, patch

from tests.test_hash_lookup import (
    ARTIFACT_ID,
    FILE_ID,
    INSTANCE_ID,
    _bundle_objects,
    _connector,
    _file_names,
    _run,
    _scan,
    _stixfile,
    _task,
)
from tests.test_report_depth import DROP_A, DROP_B, _cape_task

MARKING = "marking-definition--00000000-0000-4000-8000-0000000000aa"


def _depth_task():
    """A looked-up CAPE task that carries dropped files and a pcap artifact."""
    task = _task()
    depth = _cape_task()
    task["report"] = {
        **(task.get("report") or {}),
        "dropped": depth["report"]["dropped"],
    }
    task["sandbox_artifacts"] = depth["sandbox_artifacts"]
    return task


def _created_files(objects, sample_id):
    return [o for o in objects if o["type"] == "file" and o["id"] != sample_id]


def _hashes(files):
    return {o["hashes"]["SHA-256"].lower() for o in files if o.get("hashes")}


def test_stixfile_lookup_creates_dropped_files_with_markings():
    c = _connector(latest={"cape": _depth_task()})
    entity = {**_stixfile(), "object_marking_refs": [MARKING]}
    assert _run(c, entity) is None
    created = _created_files(_bundle_objects(c), FILE_ID)
    assert {DROP_A, DROP_B} <= _hashes(created)
    for obj in created:
        assert MARKING in obj["object_marking_refs"]


def test_stixfile_lookup_attaches_pcap_when_enabled():
    c = _connector(
        latest={"cape": _depth_task()},
        sandbox_attach_pcap=True,
        sandbox_pcap_max_size=5000,
    )
    c.polyswarm_client.download_sandbox_artifact_bytes = MagicMock(
        return_value=("cape_pcap-3.pcap", b"PCAP")
    )
    assert _run(c) is None
    c.polyswarm_client.download_sandbox_artifact_bytes.assert_called_once()
    assert any(n.endswith(".pcap") for n in _file_names(c))


def test_stixfile_lookup_no_pcap_download_by_default():
    c = _connector(latest={"cape": _depth_task()})
    c.polyswarm_client.download_sandbox_artifact_bytes = MagicMock()
    assert _run(c) is None
    c.polyswarm_client.download_sandbox_artifact_bytes.assert_not_called()


def test_artifact_reuse_creates_dropped_files_with_markings():
    c = _connector(latest={"cape": _depth_task()}, sandbox_reuse_report=True)
    c.polyswarm_client.get_scan_by_hash = MagicMock(return_value=(INSTANCE_ID, _scan()))
    entity = {
        "type": "artifact",
        "spec_version": "2.1",
        "id": ARTIFACT_ID,
        "hashes": _stixfile()["hashes"],
        "object_marking_refs": [MARKING],
    }
    opencti = {"entity_type": "Artifact", "standard_id": ARTIFACT_ID}
    with patch("connector.polyswarm_connector.time.sleep"):
        assert c._enrich_file(ARTIFACT_ID, entity, opencti, [entity]) is None
    created = _created_files(_bundle_objects(c), ARTIFACT_ID)
    assert {DROP_A, DROP_B} <= _hashes(created)
    for obj in created:
        assert MARKING in obj["object_marking_refs"]
