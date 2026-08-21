"""Tests for the passthrough ingestion logic."""

import json
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
    assert "last_run" in state


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


def test_run_schedules_process_message(connector, helper, settings):
    connector.run()

    kwargs = helper.schedule_iso.call_args.kwargs
    assert kwargs["message_callback"] == connector.process_message
    assert kwargs["duration_period"] == settings.connector.duration_period
