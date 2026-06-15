from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from connector.connector import CrowdstrikeReconConnector


def _connector():
    connector = CrowdstrikeReconConnector.__new__(CrowdstrikeReconConnector)
    connector.helper = MagicMock()
    connector.client = MagicMock()
    connector.converter_to_stix = MagicMock()
    connector.converter_to_stix.author = "author"
    connector.converter_to_stix.tlp_marking = "tlp"
    connector.config = MagicMock()
    connector.config.crowdstrike_recon.import_start_date = timedelta(days=10)
    return connector


def test_collect_intelligence_tracks_max_date_and_appends_author_tlp():
    connector = _connector()
    connector.client.query_notifications.return_value = ["id1", "id2"]
    connector.client.get_notifications_details.return_value = [
        {"notification": {"created_date": "2026-05-01T00:00:00Z"}},
        {"notification": {"created_date": "2026-05-03T00:00:00Z"}},
    ]
    connector.converter_to_stix.create_incident.return_value = ["entity"]

    stix_objects, most_recent = connector._collect_intelligence("2026-04-01T00:00:00Z")

    # The maximum created_date is returned regardless of iteration order.
    assert most_recent == "2026-05-03T00:00:00Z"
    # Author and TLP marking are appended to a non-empty bundle.
    assert "author" in stix_objects
    assert "tlp" in stix_objects
    connector.client.get_notifications_details.assert_called_once_with(["id1", "id2"])


def test_process_message_success_closes_work_without_error():
    connector = _connector()
    connector.helper.get_state.return_value = None
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.client.query_notifications.return_value = ["id1"]
    connector.client.get_notifications_details.return_value = [
        {"notification": {"created_date": "2026-05-01T00:00:00Z"}},
    ]
    connector.converter_to_stix.create_incident.return_value = ["entity"]
    connector.helper.send_stix2_bundle.return_value = ["bundle"]

    connector.process_message()

    initiate = connector.helper.api.work.initiate_work
    initiate.assert_called_once()
    assert initiate.call_args.kwargs.get("is_multipart") is True

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.args[0] == "work-1"
    assert to_processed.call_args.kwargs.get("in_error") is False

    # The most recent alert date is persisted to state.
    state = connector.helper.set_state.call_args.args[0]
    assert state["last_alert_date"] == "2026-05-01T00:00:00Z"


def test_process_message_closes_work_in_error_on_failure():
    connector = _connector()
    connector.helper.get_state.return_value = None
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.client.query_notifications.side_effect = Exception("boom")

    connector.process_message()

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.args[0] == "work-1"
    assert to_processed.call_args.kwargs.get("in_error") is True


def test_process_message_closes_work_in_error_on_interrupt():
    connector = _connector()
    connector.helper.get_state.return_value = None
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.client.query_notifications.side_effect = KeyboardInterrupt()

    with pytest.raises(SystemExit):
        connector.process_message()

    to_processed = connector.helper.api.work.to_processed
    to_processed.assert_called_once()
    assert to_processed.call_args.kwargs.get("in_error") is True
