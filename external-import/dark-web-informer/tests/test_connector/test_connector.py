"""Tests for the passthrough ingestion logic."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from connector.connector import DarkWebInformerConnector

BUNDLE = {
    "type": "bundle",
    "id": "bundle--0a1b2c3d-4e5f-6789-abcd-ef0123456789",
    "objects": [
        {"type": "identity", "id": "identity--1"},
        {"type": "indicator", "id": "indicator--2"},
    ],
}


@pytest.fixture
def connector(helper, settings):
    connector = DarkWebInformerConnector(helper=helper, settings=settings)
    connector.client = MagicMock()
    return connector


def test_init_reads_settings(helper, settings):
    connector = DarkWebInformerConnector(helper=helper, settings=settings)

    assert connector.sources == ["feed", "ransomware", "iocs"]
    assert connector.use_preview is False
    assert connector.preview_limit == 5000
    assert connector.client.api_key == "test-key"


def test_author_and_marking_are_json_serializable(connector):
    # to_stix2_object() returns STIXdatetime values json.dumps cannot encode
    json.dumps([connector.author_stix, connector.marking_stix])

    assert connector.author_stix["type"] == "identity"
    assert connector.author_stix["name"] == "Dark Web Informer"
    assert connector.author_stix["identity_class"] == "organization"
    assert connector.marking_stix["x_opencti_definition"] == "TLP:AMBER+STRICT"


def test_provenance_is_attached_to_objects(connector):
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "id": "indicator--1"},
            {"type": "domain-name", "id": "domain-name--2", "value": "evil.test"},
            {"type": "marking-definition", "id": "marking-definition--3"},
        ],
    }

    sent = connector._with_provenance(bundle, bundle["objects"])
    by_id = {o["id"]: o for o in sent["objects"]}

    # SDO gets created_by_ref, SCO gets the OpenCTI custom property
    assert by_id["indicator--1"]["created_by_ref"] == connector.author_stix["id"]
    assert (
        by_id["domain-name--2"]["x_opencti_created_by_ref"]
        == connector.author_stix["id"]
    )
    for oid in ("indicator--1", "domain-name--2"):
        assert by_id[oid]["object_marking_refs"] == [connector.marking_stix["id"]]

    # markings themselves are left alone
    assert "created_by_ref" not in by_id["marking-definition--3"]
    assert "object_marking_refs" not in by_id["marking-definition--3"]


def test_provenance_does_not_override_dwi_values(connector):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "created_by_ref": "identity--dwi-own",
                "object_marking_refs": ["marking-definition--dwi-own"],
            }
        ],
    }

    sent = connector._with_provenance(bundle, bundle["objects"])
    obj = sent["objects"][-1]

    assert obj["created_by_ref"] == "identity--dwi-own"
    assert obj["object_marking_refs"] == ["marking-definition--dwi-own"]


def test_provenance_leaves_non_dict_entries_untouched(connector):
    bundle = {"type": "bundle", "objects": ["not-an-object"]}

    sent = connector._with_provenance(bundle, bundle["objects"])

    assert sent["objects"][-1] == "not-an-object"


def test_send_bundle_forwards_bundle_unchanged(connector, helper):
    assert connector._send_bundle(BUNDLE, "work-id") == 2

    (payload,) = helper.send_stix2_bundle.call_args.args
    sent = json.loads(payload)
    kwargs = helper.send_stix2_bundle.call_args.kwargs
    assert kwargs["work_id"] == "work-id"
    assert kwargs["cleanup_inconsistent_bundle"] is True

    # the bundle envelope is untouched, only provenance objects are prepended
    assert sent["id"] == BUNDLE["id"]
    assert [o["id"] for o in sent["objects"][:2]] == [
        connector.author_stix["id"],
        connector.marking_stix["id"],
    ]
    assert [o["id"] for o in sent["objects"][2:]] == [
        o["id"] for o in BUNDLE["objects"]
    ]


@pytest.mark.parametrize("bundle", [{}, {"objects": []}, None, "not-a-bundle"])
def test_send_bundle_skips_empty_payloads(connector, helper, bundle):
    assert connector._send_bundle(bundle, "work-id") == 0
    helper.send_stix2_bundle.assert_not_called()


def test_process_message_ingests_every_source(connector, helper):
    connector.client.get_stix_bundle.return_value = BUNDLE

    connector.process_message()

    assert [c.args[0] for c in connector.client.get_stix_bundle.call_args_list] == [
        "feed",
        "ransomware",
        "iocs",
    ]
    assert helper.send_stix2_bundle.call_count == 3
    helper.api.work.initiate_work.assert_called_once()
    helper.api.work.to_processed.assert_called_once()
    assert "6 objects" in helper.api.work.to_processed.call_args.args[1]


def test_process_message_records_last_run(connector):
    connector.client.get_stix_bundle.return_value = BUNDLE

    connector.process_message()

    state = connector.helper.set_state.call_args.args[0]
    assert state["last_run"] is not None


def test_process_message_uses_preview_endpoint(connector):
    connector.use_preview = True
    connector.preview_limit = 10
    connector.sources = ["feed"]
    connector.client.get_stix_preview.return_value = BUNDLE

    connector.process_message()

    connector.client.get_stix_preview.assert_called_once_with(source="feed", limit=10)
    connector.client.get_stix_bundle.assert_not_called()


def test_process_message_marks_work_in_error_when_a_later_source_fails(
    connector, helper
):
    # First source succeeds (so a work exists), the second one blows up.
    connector.client.get_stix_bundle.side_effect = [BUNDLE, RuntimeError("API down")]

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    assert "API down" in helper.api.work.to_processed.call_args.args[1]
    helper.set_state.assert_not_called()


def test_process_message_reports_failure_before_any_work_exists(connector, helper):
    connector.client.get_stix_bundle.side_effect = RuntimeError("API down")

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called_once()
    helper.api.work.initiate_work.assert_not_called()
    helper.api.work.to_processed.assert_not_called()
    helper.set_state.assert_not_called()


def test_process_message_survives_work_initiation_failure(connector, helper):
    connector.client.get_stix_bundle.return_value = BUNDLE
    helper.api.work.initiate_work.side_effect = RuntimeError("OpenCTI unreachable")

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called_once()
    helper.send_stix2_bundle.assert_not_called()
    helper.api.work.to_processed.assert_not_called()
    helper.set_state.assert_not_called()


def test_process_message_creates_no_work_when_all_bundles_are_empty(connector, helper):
    connector.client.get_stix_bundle.return_value = {"type": "bundle", "objects": []}

    connector.process_message()

    helper.api.work.initiate_work.assert_not_called()
    helper.api.work.to_processed.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_called_once()  # the run still happened


def test_process_message_initiates_work_only_once_across_sources(connector, helper):
    connector.client.get_stix_bundle.side_effect = [
        {"type": "bundle", "objects": []},
        BUNDLE,
        BUNDLE,
    ]

    connector.process_message()

    helper.api.work.initiate_work.assert_called_once()
    assert helper.send_stix2_bundle.call_count == 2


TIMED_BUNDLE = {
    "type": "bundle",
    "id": "bundle--1",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--old",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
        },
        {"type": "domain-name", "id": "domain-name--old", "value": "old.test"},
        {
            "type": "relationship",
            "id": "relationship--old",
            "modified": "2026-01-01T00:00:00Z",
            "source_ref": "indicator--old",
            "target_ref": "domain-name--old",
        },
        {
            "type": "indicator",
            "id": "indicator--new",
            "modified": "2026-03-01T12:00:00.123Z",
            "created_by_ref": "identity--dwi",
        },
        {"type": "identity", "id": "identity--dwi", "created": "2025-01-01T00:00:00Z"},
        {"type": "domain-name", "id": "domain-name--new", "value": "new.test"},
        {
            "type": "relationship",
            "id": "relationship--new",
            "modified": "2026-03-01T00:00:00Z",
            "source_ref": "indicator--new",
            "target_ref": "domain-name--new",
        },
    ],
}


NEWEST = datetime(2026, 3, 1, 12, 0, 0, 123000, tzinfo=timezone.utc)


def _saved_cursors(helper):
    saved = helper.set_state.call_args.args[0]["cursors"]
    return {
        k: datetime.fromisoformat(v.replace("Z", "+00:00")) for k, v in saved.items()
    }


def _sent_ids(helper):
    sent = json.loads(helper.send_stix2_bundle.call_args.args[0])
    return {o["id"] for o in sent["objects"]}


def test_first_run_sends_everything_and_stores_cursor(connector, helper):
    connector.sources = ["feed"]
    connector.client.get_stix_bundle.return_value = TIMED_BUNDLE

    connector.process_message()

    assert {o["id"] for o in TIMED_BUNDLE["objects"]} <= _sent_ids(helper)
    assert _saved_cursors(helper) == {"feed": NEWEST}
    assert helper.set_state.call_args.args[0]["last_run"] is not None


def test_next_run_only_sends_changed_objects_and_their_references(connector, helper):
    connector.sources = ["feed"]
    helper.get_state.return_value = {"cursors": {"feed": "2026-02-01T00:00:00+00:00"}}
    connector.client.get_stix_bundle.return_value = TIMED_BUNDLE

    connector.process_message()

    sent = _sent_ids(helper) - {
        connector.author_stix["id"],
        connector.marking_stix["id"],
    }
    assert sent == {
        "indicator--new",
        "identity--dwi",  # referenced through created_by_ref
        "relationship--new",
        "domain-name--new",  # timestamp-less SCO pulled in by the relationship
    }


def test_run_with_nothing_new_sends_nothing(connector, helper):
    connector.sources = ["feed"]
    helper.get_state.return_value = {
        "cursors": {"feed": "2026-03-01T12:00:00.123000+00:00"},
        "last_run": "2026-03-01T13:00:00+00:00",
    }
    connector.client.get_stix_bundle.return_value = TIMED_BUNDLE

    connector.process_message()

    helper.send_stix2_bundle.assert_not_called()
    helper.api.work.initiate_work.assert_not_called()
    assert _saved_cursors(helper) == {"feed": NEWEST}


def test_cursor_of_ingested_source_survives_later_failure(connector, helper):
    connector.sources = ["feed", "iocs"]
    connector.client.get_stix_bundle.side_effect = [
        TIMED_BUNDLE,
        RuntimeError("API down"),
    ]

    connector.process_message()

    assert _saved_cursors(helper) == {"feed": NEWEST}
    assert helper.set_state.call_args.args[0]["last_run"] is None


def test_run_schedules_process_message(connector, helper, settings):
    connector.run()

    kwargs = helper.schedule_iso.call_args.kwargs
    assert kwargs["message_callback"] == connector.process_message
    assert kwargs["duration_period"] == settings.connector.duration_period


def test_connector_state_starts_empty_and_is_json_serializable():
    from connector import ConnectorState

    assert ConnectorState().last_run is None
    assert ConnectorState().cursors is None
    json.dumps(
        ConnectorState(last_run=NEWEST, cursors={"feed": NEWEST}).model_dump(
            mode="json"
        )
    )


def test_provenance_reuses_dwi_author_so_there_is_a_single_creator(connector):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "identity",
                "id": "identity--dwi-own",
                "name": "DarkWebInformer",
                "identity_class": "organization",
            },
            {
                "type": "indicator",
                "id": "indicator--1",
                "created_by_ref": "identity--dwi-own",
            },
            {"type": "indicator", "id": "indicator--2"},
            {"type": "domain-name", "id": "domain-name--3", "value": "evil.test"},
        ],
    }

    sent = connector._with_provenance(bundle, bundle["objects"])
    by_id = {o["id"]: o for o in sent["objects"]}

    assert connector.author_stix["id"] not in by_id
    identities = [o for o in sent["objects"] if o["type"] == "identity"]
    assert [i["id"] for i in identities] == ["identity--dwi-own"]
    assert by_id["indicator--2"]["created_by_ref"] == "identity--dwi-own"
    assert by_id["domain-name--3"]["x_opencti_created_by_ref"] == "identity--dwi-own"


def test_changed_since_handles_odd_timestamps_and_list_refs(connector):
    cursor = datetime(2026, 2, 1, tzinfo=timezone.utc)
    objects = [
        {
            "type": "report",
            "id": "report--new",
            "modified": "2026-03-01T00:00:00",  # no timezone: read as UTC
            "object_refs": ["indicator--ref", 42],
        },
        {"type": "indicator", "id": "indicator--ref", "modified": "not-a-date"},
        {"type": "indicator", "id": "indicator--unreferenced", "modified": "garbage"},
    ]

    kept = DarkWebInformerConnector._changed_since(objects, cursor)

    assert [o["id"] for o in kept] == ["report--new", "indicator--ref"]


def test_state_reset_from_opencti_triggers_full_import(connector, helper):
    connector.sources = ["feed"]
    connector.client.get_stix_bundle.return_value = TIMED_BUNDLE
    helper.get_state.return_value = {"cursors": {"feed": "2026-02-01T00:00:00+00:00"}}
    connector.process_message()
    assert "indicator--old" not in _sent_ids(helper)

    # "Reset state" in OpenCTI: the stored state comes back empty
    helper.get_state.return_value = {}
    connector.process_message()

    assert {o["id"] for o in TIMED_BUNDLE["objects"]} <= _sent_ids(helper)


def test_filtered_bundle_keeps_dwi_author_as_single_creator(connector, helper):
    connector.sources = ["feed"]
    helper.get_state.return_value = {"cursors": {"feed": "2026-02-01T00:00:00+00:00"}}
    connector.client.get_stix_bundle.return_value = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "identity",
                "id": "identity--dwi-own",
                "name": "DarkWebInformer",
                "identity_class": "organization",
                "created": "2025-01-01T00:00:00Z",
            },
            {
                "type": "indicator",
                "id": "indicator--old",
                "modified": "2026-01-01T00:00:00Z",
                "created_by_ref": "identity--dwi-own",
            },
            # changed since the cursor, but declares no author
            {
                "type": "indicator",
                "id": "indicator--new",
                "modified": "2026-03-01T00:00:00Z",
            },
        ],
    }

    connector.process_message()

    sent = json.loads(helper.send_stix2_bundle.call_args.args[0])["objects"]
    by_id = {o["id"]: o for o in sent}
    assert [o["id"] for o in sent if o["type"] == "identity"] == ["identity--dwi-own"]
    assert by_id["indicator--new"]["created_by_ref"] == "identity--dwi-own"
    assert "indicator--old" not in by_id
