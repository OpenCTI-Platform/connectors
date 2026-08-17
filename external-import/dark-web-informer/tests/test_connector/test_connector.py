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


def test_send_bundle_forwards_bundle_unchanged(connector, helper):
    assert connector._send_bundle(BUNDLE, "work-id") == 2

    (payload,) = helper.send_stix2_bundle.call_args.args
    assert json.loads(payload) == BUNDLE
    assert helper.send_stix2_bundle.call_args.kwargs["work_id"] == "work-id"


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


def test_process_message_marks_work_in_error_on_failure(connector, helper):
    connector.client.get_stix_bundle.side_effect = RuntimeError("API down")

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    assert "API down" in helper.api.work.to_processed.call_args.args[1]
    helper.set_state.assert_not_called()


def test_run_schedules_process_message(connector, helper, settings):
    connector.run()

    kwargs = helper.schedule_iso.call_args.kwargs
    assert kwargs["message_callback"] == connector.process_message
    assert kwargs["duration_period"] == settings.connector.duration_period
