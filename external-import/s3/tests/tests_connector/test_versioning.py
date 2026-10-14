import datetime
import io
import json
from typing import Any
from unittest.mock import MagicMock

import pytest
import s3
from pycti import Note, Vulnerability
from s3 import S3Connector, is_reference_key, merge_versions
from settings import ConnectorSettings

CVE = "CVE-2026-12345"
CVE_ID = Vulnerability.generate_id(CVE)
# Two publications of the same CVE ten minutes apart, the newer one marks it exploited
OLDER = "2026-10-01T20:01:05.711Z"
NEWER = "2026-10-01T20:11:26Z"
UTC = datetime.timezone.utc


class VersioningConnectorSettings(ConnectorSettings):
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
                    "bucket_prefixes": "ACI_Vuln",
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
    monkeypatch.setattr("s3.ConnectorSettings", VersioningConnectorSettings)
    monkeypatch.setattr("s3.boto3.client", MagicMock())

    connector = S3Connector()
    connector.helper.set_state(None)
    connector.helper.send_stix2_bundle = MagicMock()
    connector.helper.force_ping = MagicMock()
    connector.helper.api.vulnerability.list.return_value = []
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.helper.api.work.get_work.return_value = None
    set_queue_messages(connector, 0)
    return connector


def set_queue_messages(connector, messages_number):
    """Make the platform report `messages_number` messages in the connector queue."""
    connector.helper.api.connector.read.return_value = {
        "id": "connector-id",
        "connector_queue_details": {"messages_number": messages_number},
    }


def aci_vulnerability_bundle(
    modified,
    exploit_maturity,
    temporal_score,
    history,
    zero_day,
    suffix,
    created="2026-10-01T19:55:00.000Z",
):
    """An ACI vulnerability publication: its STIX IDs differ from one file to another."""
    vulnerability_id = f"vulnerability--0000000{suffix}-0000-4000-8000-000000000000"
    software_id = "software--11111111-1111-4111-8111-111111111111"
    return {
        "type": "bundle",
        "id": f"bundle--0000000{suffix}-0000-4000-8000-000000000001",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vulnerability_id,
                "created": created,
                "modified": modified,
                "name": CVE,
                "x_cvss_v3": 9.8,
                "x_cvss_v3_vector": (
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    f"/E:{exploit_maturity}/RL:O/RC:C"
                ),
                "x_cvss_v3_temporal_score": temporal_score,
                "x_zero_day": zero_day,
                "x_acti_uuid": "5f0e2a7c-58b1-4d8e-9a43-6f7b1c2d3e4f",
                "x_title": "Path traversal in Example Product",
                "x_history": history,
            },
            {
                "type": "software",
                "spec_version": "2.1",
                "id": software_id,
                "name": "Example Product",
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--0000000{suffix}-0000-4000-8000-000000000002",
                "created": "2026-10-01T19:55:00.000Z",
                "modified": modified,
                "relationship_type": "related-to",
                "source_ref": vulnerability_id,
                "target_ref": software_id,
            },
        ],
    }


FIRST_ENTRY = {"timestamp": "2026-10-01T20:01:05Z", "comment": "Initial publication"}
SECOND_ENTRY = {"timestamp": "2026-10-01T20:11:26Z", "comment": "Exploited in the wild"}
OLDER_BUNDLE = aci_vulnerability_bundle(OLDER, "U", 8.5, [FIRST_ENTRY], False, 1)
NEWER_BUNDLE = aci_vulnerability_bundle(
    NEWER, "H", 9.4, [FIRST_ENTRY, SECOND_ENTRY], True, 2
)


def put_files(connector, files):
    """Serve `files` ((key, last_modified, bundle) tuples) from the mocked bucket."""
    connector.s3_client.get_paginator.return_value.paginate.side_effect = (
        lambda Bucket, Prefix: [
            {
                "Contents": [
                    {"Key": key, "LastModified": date}
                    for key, date, _ in files
                    if key.startswith(Prefix)
                ]
            }
        ]
    )
    bodies = {key: json.dumps(bundle).encode() for key, _, bundle in files}
    connector.s3_client.get_object.side_effect = lambda Bucket, Key: {
        "Body": io.BytesIO(bodies[Key])
    }


def sent_bundles(connector):
    return [
        json.loads(call.kwargs["bundle"])
        for call in connector.helper.send_stix2_bundle.call_args_list
    ]


def objects_of_type(bundle, object_type):
    return [obj for obj in bundle["objects"] if obj["type"] == object_type]


def deleted_keys(connector):
    return [
        call.kwargs["Key"] for call in connector.s3_client.delete_object.call_args_list
    ]


@pytest.mark.parametrize(
    "files",
    [
        pytest.param(
            [
                (
                    "ACI_Vuln/a.json",
                    datetime.datetime(2026, 10, 1, 20, 11, 30, tzinfo=UTC),
                    NEWER_BUNDLE,
                ),
                (
                    "ACI_Vuln/b.json",
                    datetime.datetime(2026, 10, 1, 20, 1, 10, tzinfo=UTC),
                    OLDER_BUNDLE,
                ),
            ],
            id="newer_file_listed_first",
        ),
        pytest.param(
            [
                (
                    "ACI_Vuln/a.json",
                    datetime.datetime(2026, 10, 1, 20, 1, 10, tzinfo=UTC),
                    NEWER_BUNDLE,
                ),
                (
                    "ACI_Vuln/b.json",
                    datetime.datetime(2026, 10, 1, 20, 11, 30, tzinfo=UTC),
                    OLDER_BUNDLE,
                ),
            ],
            id="older_file_uploaded_last",
        ),
    ],
)
def test_two_versions_in_one_run_send_the_newest_version_in_every_bundle(
    connector, files
):
    """
    Two publications of the same CVE are picked up by the same run.

    Workers can apply the two bundles in any order, so both must carry the newest
    version: whichever is applied last, the CVE ends up exploited (E:H, 9.4).
    """
    put_files(connector, files)

    connector.process()

    bundles = sent_bundles(connector)
    assert len(bundles) == 2
    for bundle in bundles:
        [vulnerability] = objects_of_type(bundle, "vulnerability")
        assert vulnerability["id"] == CVE_ID
        assert vulnerability["x_opencti_modified_at"] == NEWER
        assert "/E:H/" in vulnerability["x_opencti_cvss_vector_string"]
        assert vulnerability["x_opencti_cvss_temporal_score"] == 9.4
        assert "zero-day" in vulnerability["labels"]
        notes = {note["abstract"]: note for note in objects_of_type(bundle, "note")}
        assert set(notes) == {f"{CVE} - Title", f"{CVE} - History"}
        assert "Exploited in the wild" in notes[f"{CVE} - History"]["content"]
        # The relationship of each file still points to the vulnerability
        [relationship] = objects_of_type(bundle, "relationship")
        assert relationship["relationship_type"] == "has"
        assert relationship["target_ref"] == CVE_ID
    assert "/E:U/" not in json.dumps(bundles)
    # Both files are sent and deleted, oldest upload first
    oldest_first = [key for key, _, _ in sorted(files, key=lambda f: f[1])]
    assert deleted_keys(connector) == oldest_first


def test_versions_are_merged_like_the_platform_applies_them_in_order():
    older = {
        "id": "vulnerability--older",
        "created": "2026-10-01T19:55:00.000Z",
        "modified": OLDER,
        "description": "Initial analysis",
        "x_cvss_v3_temporal_score": 8.5,
        "x_first_seen_active": "2026-09-30T00:00:00Z",
        "labels": ["accenture"],
        "x_history": [FIRST_ENTRY],
        "created_by_ref": "identity--older",
        "object_marking_refs": ["marking-definition--older"],
    }
    newer = {
        "id": "vulnerability--newer",
        "created": "2026-10-01T20:11:00Z",
        "modified": NEWER,
        "description": "Exploited in the wild",
        "x_cvss_v3_temporal_score": 9.4,
        "labels": ["zero-day"],
        "x_history": [SECOND_ENTRY, FIRST_ENTRY],
        "created_by_ref": "identity--newer",
        "object_marking_refs": ["marking-definition--newer"],
    }

    merged = merge_versions([older, newer])

    assert merged["modified"] == NEWER
    assert merged["description"] == "Exploited in the wild"
    assert merged["x_cvss_v3_temporal_score"] == 9.4
    # A field the newer version does not carry is not cleared by the platform either
    assert merged["x_first_seen_active"] == "2026-09-30T00:00:00Z"
    # The platform keeps the oldest creation date
    assert merged["created"] == "2026-10-01T19:55:00.000Z"
    # Multi-valued fields keep every value, newest first
    assert merged["labels"] == ["zero-day", "accenture"]
    assert merged["x_history"] == [SECOND_ENTRY, FIRST_ENTRY]
    # IDs and references are local to the file of each version: never merged
    assert not [key for key in merged if is_reference_key(key)]
    # The inputs are left untouched
    assert older["labels"] == ["accenture"]


def test_source_fields_mapped_to_additive_platform_fields_are_accumulated():
    """
    `x_alias` becomes aliases and the flags become labels, which the platform only
    adds: an alias or a flag of an older version is kept, whatever the newest says.
    """
    older = {"x_alias": "Old name", "x_zero_day": True, "x_wormable": False}
    middle = {"x_alias": ["Middle name", "Old name"], "x_zero_day": False}
    newer = {"x_alias": "New name", "x_zero_day": False, "x_wormable": False}

    merged = merge_versions([older, middle, newer])

    assert merged["x_alias"] == ["New name", "Middle name", "Old name"]
    assert merged["x_zero_day"] is True
    assert merged["x_wormable"] is False
    # A single version keeps its scalar form, `fix_bundle` accepts both
    assert merge_versions([newer])["x_alias"] == "New name"


def test_a_label_raised_by_an_older_version_stays_on_every_copy(connector):
    older = aci_vulnerability_bundle(OLDER, "U", 8.5, [FIRST_ENTRY], True, 1)
    newer = aci_vulnerability_bundle(
        NEWER, "H", 9.4, [FIRST_ENTRY, SECOND_ENTRY], False, 2
    )
    put_files(
        connector,
        [
            (
                "ACI_Vuln/a.json",
                datetime.datetime(2026, 10, 1, 20, 1, tzinfo=UTC),
                older,
            ),
            (
                "ACI_Vuln/b.json",
                datetime.datetime(2026, 10, 1, 20, 11, tzinfo=UTC),
                newer,
            ),
        ],
    )

    connector.process()

    bundles = sent_bundles(connector)
    assert len(bundles) == 2
    for bundle in bundles:
        [vulnerability] = objects_of_type(bundle, "vulnerability")
        assert vulnerability["x_opencti_modified_at"] == NEWER
        assert "zero-day" in vulnerability["labels"]


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        (
            "2026-10-01T19:55:00.000Z",
            "2026-10-01T20:11:00Z",
            "2026-10-01T19:55:00.000Z",
        ),
        (
            "2026-10-01T20:11:00Z",
            "2026-10-01T19:55:00.000Z",
            "2026-10-01T19:55:00.000Z",
        ),
        ("2026-10-01T19:55:00Z", "2026-10-01T19:55:00.000Z", "2026-10-01T19:55:00Z"),
        ("not a date", "2026-10-01T19:55:00Z", "2026-10-01T19:55:00Z"),
        ("2026-10-01T19:55:00Z", None, None),
    ],
)
def test_oldest_timestamp(first, second, expected):
    assert s3.oldest_timestamp(first, second) == expected


def test_note_ids_do_not_depend_on_the_creation_date_of_the_version(connector):
    """
    Note IDs derive from `created`: every copy must carry the same (oldest) one, or
    the notes of the two copies would be different notes with the same content.
    """
    republished = aci_vulnerability_bundle(
        NEWER, "H", 9.4, [FIRST_ENTRY, SECOND_ENTRY], True, 2, created=NEWER
    )
    put_files(
        connector,
        [
            (
                "ACI_Vuln/a.json",
                datetime.datetime(2026, 10, 1, 20, 1, 10, tzinfo=UTC),
                OLDER_BUNDLE,
            ),
            (
                "ACI_Vuln/b.json",
                datetime.datetime(2026, 10, 1, 20, 11, 30, tzinfo=UTC),
                republished,
            ),
        ],
    )

    connector.process()

    [first, second] = sent_bundles(connector)
    for bundle in (first, second):
        [vulnerability] = objects_of_type(bundle, "vulnerability")
        assert vulnerability["created"] == "2026-10-01T19:55:00.000Z"
        assert vulnerability["x_opencti_modified_at"] == NEWER
    first_note_ids = sorted(note["id"] for note in objects_of_type(first, "note"))
    second_note_ids = sorted(note["id"] for note in objects_of_type(second, "note"))
    assert first_note_ids == second_note_ids
    assert len(first_note_ids) == 2


def test_every_bundle_of_the_run_is_built_before_the_first_one_is_sent(connector):
    """
    A file that cannot be processed stops the run before anything is sent or deleted,
    whatever the prefix it belongs to.
    """
    connector.s3_bucket_prefixes = ["ACI_TI", "ACI_Vuln"]
    put_files(
        connector,
        [
            (
                "ACI_TI/a.json",
                datetime.datetime(2026, 10, 1, 20, 1, 10, tzinfo=UTC),
                aci_vulnerability_bundle(OLDER, "U", 8.5, [FIRST_ENTRY], False, 4),
            ),
            (
                "ACI_Vuln/b.json",
                datetime.datetime(2026, 10, 1, 20, 11, 30, tzinfo=UTC),
                NEWER_BUNDLE,
            ),
        ],
    )
    events = []
    fix_bundle = connector.fix_bundle
    connector.fix_bundle = lambda *args, **kwargs: (
        events.append("build"),
        fix_bundle(*args, **kwargs),
    )[1]
    connector.helper.send_stix2_bundle.side_effect = lambda **kwargs: events.append(
        "send"
    )

    connector.process()

    assert events == ["build", "build", "send", "send"]
    # One work per prefix, both recorded
    assert connector.helper.api.work.initiate_work.call_count == 2
    assert len(connector.helper.get_state()["pending_works"]) == 2


def test_each_copy_keeps_the_references_of_its_own_file(connector):
    """
    References point to objects of the same file, under IDs that only exist there.
    Merging them would make a copy reference objects of another file.
    """
    older_marking = "marking-definition--00000001-0000-4000-8000-00000000000a"
    newer_marking = "marking-definition--00000002-0000-4000-8000-00000000000a"
    older = {
        "type": "vulnerability",
        "id": "vulnerability--00000001-0000-4000-8000-000000000000",
        "modified": OLDER,
        "name": CVE,
        "description": "Initial analysis",
        "created_by_ref": "identity--00000001-0000-4000-8000-00000000000b",
        "object_marking_refs": [older_marking],
    }
    newer = {
        "type": "vulnerability",
        "id": "vulnerability--00000002-0000-4000-8000-000000000000",
        "modified": NEWER,
        "name": CVE,
        "description": "Exploited in the wild",
        "created_by_ref": "identity--00000002-0000-4000-8000-00000000000b",
        "object_marking_refs": [newer_marking],
    }
    note = {
        "type": "note",
        "id": "note--00000003-0000-4000-8000-000000000000",
        "modified": NEWER,
        "content": "Analyst note",
        "object_refs": [newer["id"]],
    }

    connector.resolve_versions([{"objects": [older]}, {"objects": [newer, note]}])

    assert older["description"] == newer["description"] == "Exploited in the wild"
    assert older["modified"] == newer["modified"] == NEWER
    assert older["id"] == "vulnerability--00000001-0000-4000-8000-000000000000"
    assert older["created_by_ref"] == "identity--00000001-0000-4000-8000-00000000000b"
    assert older["object_marking_refs"] == [older_marking]
    assert newer["created_by_ref"] == "identity--00000002-0000-4000-8000-00000000000b"
    assert newer["object_marking_refs"] == [newer_marking]
    assert "object_refs" not in older
    assert note["object_refs"] == [newer["id"]]


def test_unreadable_modified_is_sent_as_received(connector):
    """A non-string or malformed `modified` neither crashes the run nor is versioned."""
    connector.helper.api.vulnerability.list.return_value = [
        {
            "standard_id": CVE_ID,
            "x_opencti_stix_ids": [],
            "x_opencti_modified_at": NEWER,
        }
    ]
    bundle = aci_vulnerability_bundle(OLDER, "U", 8.5, [FIRST_ENTRY], False, 3)
    [vulnerability] = objects_of_type(bundle, "vulnerability")
    vulnerability["modified"] = [20261001]
    put_files(
        connector,
        [("ACI_Vuln/a.json", datetime.datetime(2026, 10, 2, 2, 0, tzinfo=UTC), bundle)],
    )

    assert connector.get_version(vulnerability) is None
    connector.process()

    # Not reduced to a reference: the version cannot be compared with the platform's
    [sent] = sent_bundles(connector)
    [vulnerability] = objects_of_type(sent, "vulnerability")
    assert vulnerability["id"] == CVE_ID
    assert vulnerability["x_opencti_cvss_temporal_score"] == 8.5
    assert deleted_keys(connector) == ["ACI_Vuln/a.json"]


def test_vulnerability_older_than_the_platform_is_reduced_to_a_reference(connector):
    """
    The platform already holds a newer version: the received vulnerability must not
    overwrite it, its relationships are still sent and resolve to the existing entity.
    """
    connector.helper.api.vulnerability.list.return_value = [
        {
            "id": "internal-id",
            "standard_id": CVE_ID,
            "x_opencti_stix_ids": [],
            "x_opencti_modified_at": NEWER,
        }
    ]
    put_files(
        connector,
        [
            (
                "ACI_Vuln/a.json",
                datetime.datetime(2026, 10, 2, 2, 0, tzinfo=UTC),
                OLDER_BUNDLE,
            )
        ],
    )

    connector.process()

    [bundle] = sent_bundles(connector)
    [vulnerability] = objects_of_type(bundle, "vulnerability")
    assert vulnerability["id"] == CVE_ID
    assert vulnerability["name"] == CVE
    assert not [key for key in vulnerability if key.startswith("x_opencti_cvss")]
    assert "x_opencti_modified_at" not in vulnerability
    assert "labels" not in vulnerability
    assert "external_references" not in vulnerability
    assert objects_of_type(bundle, "note") == []
    [relationship] = objects_of_type(bundle, "relationship")
    assert relationship["target_ref"] == CVE_ID
    assert len(objects_of_type(bundle, "software")) == 1
    assert deleted_keys(connector) == ["ACI_Vuln/a.json"]


def test_vulnerability_newer_than_the_platform_is_sent_in_full(connector):
    connector.helper.api.vulnerability.list.return_value = [
        {
            "standard_id": CVE_ID,
            "x_opencti_stix_ids": [],
            "x_opencti_modified_at": OLDER,
        }
    ]
    put_files(
        connector,
        [
            (
                "ACI_Vuln/a.json",
                datetime.datetime(2026, 10, 2, 2, 0, tzinfo=UTC),
                NEWER_BUNDLE,
            )
        ],
    )

    connector.process()

    [bundle] = sent_bundles(connector)
    [vulnerability] = objects_of_type(bundle, "vulnerability")
    assert vulnerability["x_opencti_modified_at"] == NEWER
    assert vulnerability["x_opencti_cvss_temporal_score"] == 9.4
    assert len(objects_of_type(bundle, "note")) == 2


def test_a_newer_version_takes_the_creation_date_held_by_the_platform(connector):
    """
    Across runs: the note IDs derive from `created`, and the platform keeps the oldest
    creation date. A newer publication with a later `created` must generate the same
    notes as the version the platform already holds, not new ones.
    """
    platform_created = "2026-09-30T08:00:00.000Z"
    connector.helper.api.vulnerability.list.return_value = [
        {
            "standard_id": CVE_ID,
            "x_opencti_stix_ids": [],
            "x_opencti_modified_at": OLDER,
            "created": platform_created,
        }
    ]
    republished = aci_vulnerability_bundle(
        NEWER, "H", 9.4, [FIRST_ENTRY, SECOND_ENTRY], True, 2, created=NEWER
    )
    put_files(
        connector,
        [
            (
                "ACI_Vuln/a.json",
                datetime.datetime(2026, 10, 2, 2, 0, tzinfo=UTC),
                republished,
            )
        ],
    )

    connector.process()

    [bundle] = sent_bundles(connector)
    [vulnerability] = objects_of_type(bundle, "vulnerability")
    assert vulnerability["created"] == platform_created
    assert vulnerability["x_opencti_modified_at"] == NEWER
    acti_uuid = "5f0e2a7c-58b1-4d8e-9a43-6f7b1c2d3e4f"
    assert sorted(note["id"] for note in objects_of_type(bundle, "note")) == sorted(
        Note.generate_id(platform_created, f"{acti_uuid} - {note_type}")
        for note_type in ("Title", "History")
    )


def test_platform_versions_are_read_in_batches(connector):
    bundle = {
        "type": "bundle",
        "id": "bundle--22222222-2222-4222-8222-222222222222",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{index:08d}-0000-4000-8000-000000000000",
                "created": OLDER,
                "modified": OLDER,
                "name": f"CVE-2026-{index:05d}",
            }
            for index in range(250)
        ],
    }
    put_files(
        connector,
        [("ACI_Vuln/a.json", datetime.datetime(2026, 10, 2, 2, 0, tzinfo=UTC), bundle)],
    )

    connector.process()

    calls = connector.helper.api.vulnerability.list.call_args_list
    assert [len(call.kwargs["filters"]["filters"][0]["values"]) for call in calls] == [
        100,
        100,
        50,
    ]
    connector.helper.api.vulnerability.read.assert_not_called()


def test_files_are_listed_across_pages_and_processed_oldest_first(
    connector, monkeypatch
):
    monkeypatch.setattr(s3, "MAX_FILES_PER_RUN", 2)
    connector.s3_client.get_paginator.return_value.paginate.return_value = [
        {
            "Contents": [
                {
                    "Key": "ACI_Vuln/a.json",
                    "LastModified": datetime.datetime(2026, 10, 1, 22, tzinfo=UTC),
                },
                {
                    "Key": "ACI_Vuln/b.json",
                    "LastModified": datetime.datetime(2026, 10, 1, 20, tzinfo=UTC),
                },
            ]
        },
        {
            "Contents": [
                {
                    "Key": "ACI_Vuln/c.json",
                    "LastModified": datetime.datetime(2026, 10, 1, 21, tzinfo=UTC),
                },
            ]
        },
    ]

    files = connector.list_files("ACI_Vuln")

    assert [f["Key"] for f in files] == ["ACI_Vuln/b.json", "ACI_Vuln/c.json"]
    connector.s3_client.get_paginator.assert_called_once_with("list_objects_v2")


def test_work_is_multipart_and_waited_for_by_the_next_run(connector):
    put_files(
        connector,
        [
            (
                "ACI_Vuln/a.json",
                datetime.datetime(2026, 10, 1, 20, 11, 30, tzinfo=UTC),
                NEWER_BUNDLE,
            )
        ],
    )

    connector.process()

    connector.helper.api.work.initiate_work.assert_called_once()
    assert connector.helper.api.work.initiate_work.call_args.kwargs == {
        "is_multipart": True
    }
    [pending] = connector.helper.get_state()["pending_works"]
    assert pending["work_id"] == "work-1"
    connector.helper.force_ping.assert_called()


def test_older_version_published_after_a_run_waits_and_is_then_superseded(connector):
    """
    Across runs: the newer publication was sent by a previous run and is still in the
    queue when the older one reaches the bucket. The older file must wait, then be
    compared with the platform once the newer version is applied.
    """
    put_files(
        connector,
        [
            (
                "ACI_Vuln/a.json",
                datetime.datetime(2026, 10, 1, 20, 11, 30, tzinfo=UTC),
                NEWER_BUNDLE,
            )
        ],
    )
    connector.process()
    assert len(sent_bundles(connector)) == 1

    put_files(
        connector,
        [
            (
                "ACI_Vuln/b.json",
                datetime.datetime(2026, 10, 1, 20, 12, tzinfo=UTC),
                OLDER_BUNDLE,
            )
        ],
    )
    connector.helper.api.work.get_work.return_value = {
        "id": "work-1",
        "status": "progress",
        "tracking": {"import_expected_number": "1", "import_processed_number": "0"},
    }
    connector.process()
    # Nothing sent or deleted while the newer version waits in the queue
    assert len(sent_bundles(connector)) == 1
    assert deleted_keys(connector) == ["ACI_Vuln/a.json"]

    connector.helper.api.work.get_work.return_value = {
        "id": "work-1",
        "status": "complete",
        "tracking": {"import_expected_number": 1, "import_processed_number": 1},
    }
    connector.helper.api.vulnerability.list.return_value = [
        {
            "standard_id": CVE_ID,
            "x_opencti_stix_ids": [],
            "x_opencti_modified_at": NEWER,
        }
    ]
    connector.process()

    bundles = sent_bundles(connector)
    assert len(bundles) == 2
    [vulnerability] = objects_of_type(bundles[1], "vulnerability")
    assert "x_opencti_cvss_vector_string" not in vulnerability
    assert objects_of_type(bundles[1], "note") == []
    assert deleted_keys(connector) == ["ACI_Vuln/a.json", "ACI_Vuln/b.json"]


@pytest.mark.parametrize(
    "work",
    [
        pytest.param(None, id="work_deleted"),
        pytest.param(
            {"status": "complete", "tracking": {}},
            id="work_complete",
        ),
        pytest.param(
            {
                "status": "progress",
                "tracking": {"import_expected_number": 3, "import_processed_number": 3},
            },
            id="all_bundles_processed_without_to_processed",
        ),
    ],
)
def test_finished_works_are_released(connector, work):
    connector.helper.set_state(
        {"pending_works": [{"work_id": "work-0", "processed": 0}]}
    )
    connector.helper.api.work.get_work.return_value = work

    assert connector.has_pending_works() is False
    assert connector.helper.get_state()["pending_works"] == []


def stall_work(connector):
    """A work of a previous run with no progress for twice the stall timeout."""
    stalled_since = datetime.datetime.now(UTC) - s3.WORK_STALL_TIMEOUT * 2
    connector.helper.set_state(
        {
            "pending_works": [
                {
                    "work_id": "work-0",
                    "processed": 1,
                    "progress_at": stalled_since.isoformat(),
                }
            ]
        }
    )
    connector.helper.api.work.get_work.return_value = {
        "status": "progress",
        "tracking": {"import_expected_number": 2, "import_processed_number": 1},
    }
    return stalled_since


def test_stalled_work_is_released_once_the_queue_is_empty(connector):
    """Its messages are gone: nothing older can be applied after the new files."""
    stall_work(connector)
    set_queue_messages(connector, 0)

    assert connector.has_pending_works() is False
    assert connector.helper.get_state()["pending_works"] == []


def test_stalled_work_is_waited_for_while_the_queue_holds_messages(connector):
    """
    Workers down for more than the timeout: the messages of the work are still in
    the queue and would be applied after the new files, so the wait goes on.
    """
    stalled_since = stall_work(connector)
    set_queue_messages(connector, 3)

    assert connector.has_pending_works() is True
    [pending] = connector.helper.get_state()["pending_works"]
    assert pending["work_id"] == "work-0"
    # The stall is not reset: the next run checks the queue again
    assert pending["progress_at"] == stalled_since.isoformat()


@pytest.mark.parametrize(
    "connector_details",
    [
        pytest.param(None, id="no_connector"),
        pytest.param({"id": "connector-id"}, id="no_queue_details"),
        pytest.param(
            {"connector_queue_details": {"messages_number": None}},
            id="no_messages_number",
        ),
        pytest.param(Exception("API unreachable"), id="read_fails"),
    ],
)
def test_stalled_work_is_released_when_the_queue_size_is_unknown(
    connector, connector_details
):
    stall_work(connector)
    if isinstance(connector_details, Exception):
        connector.helper.api.connector.read.side_effect = connector_details
    else:
        connector.helper.api.connector.read.return_value = connector_details

    assert connector.has_pending_works() is False


def test_queue_is_only_read_for_a_stalled_work(connector):
    stall_work(connector)
    connector.helper.api.work.get_work.return_value = {
        "status": "progress",
        "tracking": {"import_expected_number": 2, "import_processed_number": 1},
    }
    # Fresh progress: not stalled
    connector.helper.set_state(
        {
            "pending_works": [
                {
                    "work_id": "work-0",
                    "processed": 1,
                    "progress_at": datetime.datetime.now(UTC).isoformat(),
                }
            ]
        }
    )

    assert connector.has_pending_works() is True
    connector.helper.api.connector.read.assert_not_called()


def test_progressing_work_is_waited_for(connector):
    long_ago = datetime.datetime.now(UTC) - s3.WORK_STALL_TIMEOUT * 2
    connector.helper.set_state(
        {
            "pending_works": [
                {
                    "work_id": "work-0",
                    "processed": 1,
                    "progress_at": long_ago.isoformat(),
                }
            ]
        }
    )
    connector.helper.api.work.get_work.return_value = {
        "status": "progress",
        "tracking": {"import_expected_number": 5, "import_processed_number": 2},
    }

    assert connector.has_pending_works() is True
    [pending] = connector.helper.get_state()["pending_works"]
    assert pending["processed"] == 2
    assert s3.parse_stix_timestamp(pending["progress_at"]) > long_ago
