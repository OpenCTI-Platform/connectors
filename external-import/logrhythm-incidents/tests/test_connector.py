from unittest.mock import MagicMock, patch

from connector.connector import LogRhythmIncidentsConnector


def _make_connector():
    helper = MagicMock()
    with patch("connector.connector.LogRhythmClient") as client_cls:
        connector = LogRhythmIncidentsConnector(config=MagicMock(), helper=helper)
    connector.client = client_cls.return_value
    return connector, helper, connector.client


def test_collect_intelligence_builds_objects():
    connector, _, client = _make_connector()
    client.get_cases.return_value = [{"name": "Case A", "number": "1", "id": "c1"}]
    client.get_case_alarms.return_value = [
        {"alarmId": "a1", "alarmRuleName": "Brute force", "riskScore": 85}
    ]

    objects = connector._collect_intelligence()
    types = [o["type"] for o in objects]

    assert "incident" in types  # alarm -> Incident
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
    client.get_cases.return_value = [{"name": "Case A", "number": "1"}]
    client.get_case_alarms.return_value = []

    connector.process_message()

    helper.send_stix2_bundle.assert_called_once()
    helper.set_state.assert_called_once()
    helper.api.work.to_processed.assert_called_once()


def test_process_message_handles_errors():
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-1"
    client.get_cases.side_effect = RuntimeError("boom")

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called()


def test_run_schedules_process():
    connector, helper, _ = _make_connector()

    connector.run()

    helper.schedule_process.assert_called_once()
