from unittest.mock import MagicMock, patch

from connector.connector import ArcSightIncidentsConnector


def _make_connector():
    helper = MagicMock()
    with patch("connector.connector.ArcSightClient") as client_cls:
        connector = ArcSightIncidentsConnector(config=MagicMock(), helper=helper)
    connector.client = client_cls.return_value
    return connector, helper, connector.client


def test_collect_intelligence_builds_objects():
    connector, _, client = _make_connector()
    client.get_cases.return_value = [
        {"name": "Case A", "resourceid": "1", "eventIDs": ["e1"]}
    ]
    client.get_case_events.return_value = [
        {"name": "Suspicious login", "eventId": "e1", "priority": 9}
    ]

    objects = connector._collect_intelligence()
    types = [o["type"] for o in objects]

    assert "incident" in types  # event -> Incident
    assert "case-incident" in types  # case -> Case-Incident
    assert "identity" in types  # author appended

    case = next(o for o in objects if o["type"] == "case-incident")
    incident = next(o for o in objects if o["type"] == "incident")
    assert incident["id"] in case["object_refs"]


def test_collect_intelligence_empty():
    connector, _, client = _make_connector()
    client.get_cases.return_value = []

    assert connector._collect_intelligence() == []


def test_process_message_sends_bundle():
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.return_value = "bundle"
    client.get_cases.return_value = [{"name": "Case A", "resourceid": "1"}]
    client.get_case_events.return_value = []

    connector.process_message()

    helper.send_stix2_bundle.assert_called_once()
    helper.set_state.assert_called_once()
    helper.api.work.to_processed.assert_called_once()


def test_process_message_skips_work_when_no_data():
    # No data collected: no work must be initiated (no empty jobs), but the
    # state must still be updated so the schedule advances.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    client.get_cases.return_value = []

    connector.process_message()

    helper.api.work.initiate_work.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_called_once()


def test_process_message_handles_errors_before_work():
    # A collection failure happens before any work is initiated, so there is
    # nothing to finalize - but the error must be logged and not raised.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    client.get_cases.side_effect = RuntimeError("boom")

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called()
    helper.api.work.initiate_work.assert_not_called()
    helper.api.work.to_processed.assert_not_called()


def test_process_message_finalizes_work_in_error_when_send_fails():
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.return_value = "bundle"
    helper.send_stix2_bundle.side_effect = RuntimeError("boom")
    client.get_cases.return_value = [{"name": "Case A", "resourceid": "1"}]
    client.get_case_events.return_value = []

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called()
    # the initiated work must be finalized (in error) rather than left dangling
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_run_schedules_process():
    connector, helper, _ = _make_connector()

    connector.run()

    helper.schedule_process.assert_called_once()
