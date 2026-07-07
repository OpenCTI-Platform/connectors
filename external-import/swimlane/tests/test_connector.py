from unittest.mock import MagicMock, patch

import pytest
from connector.connector import SwimlaneConnector


def _make_connector():
    helper = MagicMock()
    with patch("connector.connector.SwimlaneClient") as client_cls:
        connector = SwimlaneConnector(config=MagicMock(), helper=helper)
    connector.client = client_cls.return_value
    return connector, helper, connector.client


def test_collect_intelligence_builds_objects():
    connector, _, client = _make_connector()
    client.get_records.return_value = [{"trackingId": "INC-1", "id": "1"}]

    objects = connector._collect_intelligence()
    types = [o["type"] for o in objects]

    assert "case-incident" in types
    assert "identity" in types  # author appended


def test_collect_intelligence_empty():
    connector, _, client = _make_connector()
    client.get_records.return_value = []

    assert connector._collect_intelligence() == []


def test_process_message_sends_bundle():
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.return_value = "bundle"
    client.get_records.return_value = [{"trackingId": "INC-1", "id": "1"}]

    connector.process_message()

    helper.send_stix2_bundle.assert_called_once()
    helper.set_state.assert_called_once()
    helper.api.work.to_processed.assert_called_once()


def test_process_message_empty_run_creates_no_work():
    # No records -> no work is initiated (avoids empty jobs in OpenCTI),
    # but the run is still a success and the state advances.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    client.get_records.return_value = []

    connector.process_message()

    helper.api.work.initiate_work.assert_not_called()
    helper.api.work.to_processed.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_called_once()


def test_process_message_handles_errors():
    # A fetch failure happens before any work is initiated, so there is no
    # work to finalize; the error is logged and the state does not advance.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    client.get_records.side_effect = RuntimeError("boom")

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called()
    helper.api.work.initiate_work.assert_not_called()
    helper.api.work.to_processed.assert_not_called()
    helper.set_state.assert_not_called()


def test_process_message_failure_after_work_marks_in_error():
    # A failure after the work is initiated must finalize the work in error
    # rather than reporting a successful run.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-1"
    client.get_records.return_value = [{"trackingId": "INC-1", "id": "1"}]
    helper.send_stix2_bundle.side_effect = RuntimeError("boom")

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called()
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True
    helper.set_state.assert_not_called()


def test_process_message_interrupt_marks_work_in_error():
    # An interrupted run (KeyboardInterrupt/SystemExit after the work is
    # initiated) must finalize the work in error, not as a success.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {}
    helper.api.work.initiate_work.return_value = "work-1"
    client.get_records.return_value = [{"trackingId": "INC-1", "id": "1"}]
    helper.send_stix2_bundle.side_effect = KeyboardInterrupt()

    with pytest.raises(SystemExit):
        connector.process_message()

    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_run_schedules_process():
    connector, helper, _ = _make_connector()

    connector.run()

    helper.schedule_process.assert_called_once()
