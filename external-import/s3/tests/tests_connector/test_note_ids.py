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
    assert note["id"] == Note.generate_id(
        CREATED, f"{ACTI_UUID} - {ACTI_UUID} - {note_type}"
    )
    # ID given by previous versions on the updates, and before 2026-01-28
    assert note["x_opencti_stix_ids"] == [
        Note.generate_id(CREATED, f"{ACTI_UUID} - {note_type}")
    ]


@pytest.mark.parametrize("note_type", NOTE_TYPES)
def test_cve_note_ids_are_unchanged(connector, note_type):
    notes = notes_by_abstract(connector, acti_bundle("CVE-2026-12345", [FIRST_ENTRY]))

    note = notes[f"CVE-2026-12345 - {note_type}"]
    assert note["id"] == Note.generate_id(CREATED, f"{ACTI_UUID} - {note_type}")
    assert "x_opencti_stix_ids" not in note


def test_non_cve_entries_sharing_an_acti_uuid_keep_their_own_notes(connector):
    first = notes_by_abstract(connector, acti_bundle("ACME-2026-0001", [FIRST_ENTRY]))
    second = notes_by_abstract(connector, acti_bundle("ACME-2026-0002", [FIRST_ENTRY]))

    for note_type in NOTE_TYPES:
        assert (
            first[f"ACME-2026-0001 - {note_type}"]["id"]
            != second[f"ACME-2026-0002 - {note_type}"]["id"]
        )
