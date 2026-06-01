"""Tests for the background CaseIncident status tracker."""

import threading
from unittest.mock import MagicMock

import pytest
from connector.case_status_tracker import TERMINAL_STATUSES, CaseStatusTracker


@pytest.fixture
def helper():
    return MagicMock()


@pytest.fixture
def client():
    return MagicMock()


@pytest.fixture
def tracker(helper, client):
    return CaseStatusTracker(
        helper=helper, client=client, poll_interval=0.01, lock=threading.Lock()
    )


class TestRegisterCase:
    def test_register_writes_state(self, tracker, helper):
        helper.get_state.return_value = {}
        tracker.register_case("HV-1", "case-incident--1", initial_status="open")
        saved = helper.set_state.call_args[0][0]
        assert saved["tracked_cases"]["HV-1"]["case_incident_id"] == "case-incident--1"
        assert saved["tracked_cases"]["HV-1"]["last_known_status"] == "open"

    def test_register_cases_batch_preserves_existing_status(self, tracker, helper):
        helper.get_state.return_value = {
            "tracked_cases": {
                "HV-1": {
                    "case_incident_id": "case-incident--1",
                    "last_known_status": "open:triage",
                    "registered_at": "t0",
                }
            }
        }
        tracker.register_cases(
            [
                {
                    "ticket_id": "HV-1",
                    "case_incident_id": "case-incident--1",
                    "initial_status": "open",
                },
                {
                    "ticket_id": "HV-2",
                    "case_incident_id": "case-incident--2",
                    "initial_status": "new",
                },
            ]
        )
        saved = helper.set_state.call_args[0][0]["tracked_cases"]
        # An already-tracked case keeps its last known status (not reset).
        assert saved["HV-1"]["last_known_status"] == "open:triage"
        assert saved["HV-1"]["registered_at"] == "t0"
        # A new case is seeded with its initial status.
        assert saved["HV-2"]["last_known_status"] == "new"
        # The whole batch is a single state write.
        assert helper.set_state.call_count == 1

    def test_register_cases_empty_is_noop(self, tracker, helper):
        tracker.register_cases([])
        helper.set_state.assert_not_called()


class TestCheckAllCases:
    def test_empty_does_nothing(self, tracker, helper):
        helper.get_state.return_value = {}
        tracker._check_single_case = MagicMock()
        tracker._check_all_cases()
        tracker._check_single_case.assert_not_called()

    def test_iterates(self, tracker, helper):
        helper.get_state.return_value = {"tracked_cases": {"HV-1": {}}}
        tracker._check_single_case = MagicMock()
        tracker._check_all_cases()
        tracker._check_single_case.assert_called_once()

    def test_single_error_caught(self, tracker, helper):
        helper.get_state.return_value = {"tracked_cases": {"HV-1": {}}}
        tracker._check_single_case = MagicMock(side_effect=RuntimeError("boom"))
        tracker._check_all_cases()
        helper.connector_logger.error.assert_called()


class TestCheckSingleCase:
    def test_no_data_returns(self, tracker, client):
        client.get_issue.return_value = {}
        tracker._update_case_label = MagicMock()
        tracker._check_single_case("HV-1", {"last_known_status": "open"})
        tracker._update_case_label.assert_not_called()

    def test_no_change_returns(self, tracker, client):
        client.get_issue.return_value = {"status": "open"}
        tracker._update_case_label = MagicMock()
        tracker._check_single_case("HV-1", {"last_known_status": "open"})
        tracker._update_case_label.assert_not_called()

    def test_status_with_progress_combined(self, tracker, helper, client):
        client.get_issue.return_value = {"status": "open", "progress_status": "triage"}
        helper.get_state.return_value = {
            "tracked_cases": {"HV-1": {"last_known_status": "open"}}
        }
        tracker._update_case_label = MagicMock()
        tracker._check_single_case(
            "HV-1", {"case_incident_id": "c1", "last_known_status": "open"}
        )
        tracker._update_case_label.assert_called_once_with("c1", "open:triage", "open")
        saved = helper.set_state.call_args[0][0]
        assert saved["tracked_cases"]["HV-1"]["last_known_status"] == "open:triage"

    def test_terminal_status_removes_case(self, tracker, helper, client):
        terminal = next(iter(TERMINAL_STATUSES))
        client.get_issue.return_value = {"status": terminal}
        helper.get_state.return_value = {
            "tracked_cases": {"HV-1": {"last_known_status": "open"}}
        }
        tracker._update_case_label = MagicMock()
        tracker._check_single_case(
            "HV-1", {"case_incident_id": "c1", "last_known_status": "open"}
        )
        saved = helper.set_state.call_args[0][0]
        assert "HV-1" not in saved["tracked_cases"]


class TestUpdateCaseLabel:
    def test_no_case_id_returns(self, tracker, helper):
        tracker._update_case_label("", "open", "unknown")
        helper.api.stix_domain_object.add_label.assert_not_called()

    def test_adds_and_removes(self, tracker, helper):
        tracker._update_case_label("c1", "fixed", "open")
        helper.api.stix_domain_object.remove_label.assert_called_once_with(
            id="c1", label_name="status:open"
        )
        helper.api.stix_domain_object.add_label.assert_called_once_with(
            id="c1", label_name="status:fixed"
        )

    def test_add_failure_logged(self, tracker, helper):
        helper.api.stix_domain_object.add_label.side_effect = RuntimeError("down")
        tracker._update_case_label("c1", "fixed", "open")
        helper.connector_logger.error.assert_called()


class TestPollLoopLifecycle:
    def test_poll_loop_runs_then_stops(self, tracker):
        calls = []

        def fake_check():
            calls.append(1)
            tracker._stop_event.set()

        tracker._check_all_cases = fake_check
        tracker.start()
        tracker._thread.join(timeout=2)
        assert calls == [1]

    def test_poll_loop_catches_errors(self, tracker, helper):
        def fake_check():
            tracker._stop_event.set()
            raise RuntimeError("cycle error")

        tracker._check_all_cases = fake_check
        tracker.start()
        tracker._thread.join(timeout=2)
        helper.connector_logger.error.assert_called()

    def test_stop_without_thread(self, tracker):
        tracker.stop()
