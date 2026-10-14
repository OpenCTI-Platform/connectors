import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import Note
from s3 import S3Connector
from settings import ConnectorSettings

ACTI_UUID = "5f0e2a7c-58b1-4d8e-9a43-6f7b1c2d3e4f"
CREATED = "2026-09-15T08:00:00.000Z"
FIRST_ENTRY = {"timestamp": "2026-09-15T08:00:00Z", "comment": "Initial publication"}
SECOND_ENTRY = {"timestamp": "2026-10-01T10:00:00Z", "comment": "CVSS 3.0 -> 3.1"}
NOTE_TYPES = ["Title", "Analysis", "History"]

# IDs the notes of ACTI_UUID, created on CREATED, hold in the platforms fed by previous
# versions of the connector. Pinned as literals: a change of these keys or of
# `Note.generate_id` would leave those notes unmatched, and duplicated.
# `Note.generate_id(CREATED, f"{ACTI_UUID} - {note_type}")`: every version before
# 2026-01-28, then every run after the first import, and CVE entries to this day
UUID_ONLY_IDS = {
    "Title": "note--856c6b5b-5668-50f6-99aa-aedc56f0c437",
    "Analysis": "note--7216b06b-0287-5818-89d7-e2ecffa955af",
    "History": "note--db17d8eb-0570-53cd-aeb1-7a51dae5c6e7",
}
# `Note.generate_id(CREATED, f"{ACTI_UUID} - {ACTI_UUID} - {note_type}")`: the first
# import of a non-CVE entry named by its ACTI UUID since 2026-01-28
UUID_AND_NAME_IDS = {
    "Title": "note--79d3852a-0e0c-5cc5-a16b-f215d51ffff4",
    "Analysis": "note--13d57fd1-7474-59ff-8fff-640fd339e6d9",
    "History": "note--34d0f47b-d079-560d-9402-b378e8b1a405",
}


class NoteIdsConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "log_level": "error"},
                "s3": {
                    "access_key_id": "test-access-key-id",
                    "secret_access_key": "test-secret-access-key",
                    "bucket_name": "test-bucket",
                },
            }
        )


@pytest.fixture
def connector(monkeypatch):
    module_import_path = "pycti.connector.opencti_connector_helper"
    monkeypatch.setattr(f"{module_import_path}.killProgramHook", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.sched.scheduler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.ConnectorInfo", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIApiClient", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIConnector", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.OpenCTIMetricHandler", MagicMock())
    monkeypatch.setattr(f"{module_import_path}.PingAlive", MagicMock())
    monkeypatch.setattr("s3.ConnectorSettings", NoteIdsConnectorSettings)
    monkeypatch.setattr("s3.boto3.client", MagicMock())

    connector = S3Connector()
    connector.helper.api.vulnerability.read.return_value = None
    return connector


def acti_bundle(name, history):
    return {
        "type": "bundle",
        "id": "bundle--3f1c2b7a-9d4e-4a6b-8c2d-1e5f7a9b0c3d",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": "vulnerability--8a2b4c6d-1e3f-4a5b-9c7d-2e4f6a8b0c1d",
                "created": CREATED,
                "modified": history[0]["timestamp"],
                "name": name,
                "x_acti_uuid": ACTI_UUID,
                "x_title": "Remote code execution in Example Product",
                "x_analysis": "Exploitation requires network access.",
                "x_history": history,
            }
        ],
    }


def notes_by_abstract(connector, bundle):
    fixed_bundle = json.loads(connector.fix_bundle(json.dumps(bundle)))
    return {
        obj["abstract"]: obj for obj in fixed_bundle["objects"] if obj["type"] == "note"
    }


def matching_ids(note):
    """Every ID the platform matches an incoming note on: its STIX ID and its aliases."""
    return {note["id"], *note.get("x_opencti_stix_ids", [])}


def test_non_cve_note_ids_do_not_change_when_the_vulnerability_is_updated(connector):
    """
    #7830: the first import created the notes with one ID, the first update looked
    the notes up in the platform, found them and switched to another ID. With new
    content, the platform could not match the notes and created duplicates.
    """
    first_import = notes_by_abstract(connector, acti_bundle(ACTI_UUID, [FIRST_ENTRY]))
    # The platform now holds the notes of the first import
    connector.helper.api.note.list.return_value = [{"id": "note-of-the-first-import"}]
    update = notes_by_abstract(
        connector, acti_bundle(ACTI_UUID, [SECOND_ENTRY, FIRST_ENTRY])
    )

    abstracts = {f"{ACTI_UUID} - {note_type}" for note_type in NOTE_TYPES}
    assert set(first_import) == set(update) == abstracts
    for abstract in abstracts:
        assert update[abstract]["id"] == first_import[abstract]["id"]
        assert (
            update[abstract]["x_opencti_stix_ids"]
            == first_import[abstract]["x_opencti_stix_ids"]
        )
    history = f"{ACTI_UUID} - History"
    assert update[history]["content"] != first_import[history]["content"]
    connector.helper.api.note.list.assert_not_called()


@pytest.mark.parametrize("note_type", NOTE_TYPES)
def test_non_cve_notes_match_the_notes_created_by_previous_versions(
    connector, note_type
):
    """Existing notes are updated in place, whichever of the two former IDs they have."""
    notes = notes_by_abstract(connector, acti_bundle(ACTI_UUID, [FIRST_ENTRY]))

    note = notes[f"{ACTI_UUID} - {note_type}"]
    # ID given by previous versions on the first import of the vulnerability
    assert note["id"] == UUID_AND_NAME_IDS[note_type]
    assert note["id"] == Note.generate_id(
        CREATED, f"{ACTI_UUID} - {ACTI_UUID} - {note_type}"
    )
    # ID given by previous versions on the updates, and before 2026-01-28
    assert note["x_opencti_stix_ids"] == [UUID_ONLY_IDS[note_type]]
    assert note["x_opencti_stix_ids"] == [
        Note.generate_id(CREATED, f"{ACTI_UUID} - {note_type}")
    ]


@pytest.mark.parametrize("note_type", NOTE_TYPES)
def test_cve_note_ids_are_unchanged(connector, note_type):
    notes = notes_by_abstract(connector, acti_bundle("CVE-2026-12345", [FIRST_ENTRY]))

    note = notes[f"CVE-2026-12345 - {note_type}"]
    assert note["id"] == UUID_ONLY_IDS[note_type]
    assert note["id"] == Note.generate_id(CREATED, f"{ACTI_UUID} - {note_type}")
    assert "x_opencti_stix_ids" not in note


def test_non_cve_entries_sharing_an_acti_uuid_keep_their_own_notes(connector):
    """
    The platform matches an incoming note on its ID and on its aliases, so the notes
    of entries sharing an ACTI UUID must not have a single ID in common, or the
    platform would collapse them into one note. The ACTI UUID only ID that previous
    versions gave to all of them is claimed by the entry named by its ACTI UUID alone.
    """
    by_uuid = notes_by_abstract(connector, acti_bundle(ACTI_UUID, [FIRST_ENTRY]))
    first = notes_by_abstract(connector, acti_bundle("ACME-2026-0001", [FIRST_ENTRY]))
    second = notes_by_abstract(connector, acti_bundle("ACME-2026-0002", [FIRST_ENTRY]))

    for note_type in NOTE_TYPES:
        notes = [
            by_uuid[f"{ACTI_UUID} - {note_type}"],
            first[f"ACME-2026-0001 - {note_type}"],
            second[f"ACME-2026-0002 - {note_type}"],
        ]
        ids = [matching_ids(note) for note in notes]
        # Pairwise disjoint: no ID, STIX ID or alias, is shared by two entries
        assert len(set().union(*ids)) == sum(len(note_ids) for note_ids in ids)
        assert notes[0]["x_opencti_stix_ids"] == [UUID_ONLY_IDS[note_type]]
        assert "x_opencti_stix_ids" not in notes[1]
        assert "x_opencti_stix_ids" not in notes[2]
