"""Tests for the HackerView connector orchestration logic."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.connector import CTM360HackerViewConnector
from pydantic import SecretStr


def make_config(**hv_overrides):
    hv = SimpleNamespace(
        api_base_url="https://hackerview.example.com",
        api_key=SecretStr("secret"),
        import_issues=True,
        import_resolved_issues=True,
        import_domain_assets=True,
        import_host_assets=True,
        import_ip_assets=True,
        status_poll_interval=timedelta(hours=1),
        enable_status_tracking=False,
    )
    for key, value in hv_overrides.items():
        setattr(hv, key, value)
    connector = SimpleNamespace(id="conn-1", duration_period=timedelta(hours=24))
    return SimpleNamespace(ctm360_hackerview_feed=hv, connector=connector)


@pytest.fixture
def helper():
    helper = MagicMock()
    helper.api.work.initiate_work.return_value = "work-1"
    helper.connect_id = "conn-1"
    return helper


def build_connector(helper, **hv_overrides):
    connector = CTM360HackerViewConnector(
        config=make_config(**hv_overrides), helper=helper
    )
    connector.client = MagicMock()
    connector.converter = MagicMock()
    connector.converter.issue_case_metadata = []
    return connector


class TestInit:
    def test_author_id_comes_from_converter(self, helper):
        connector = CTM360HackerViewConnector(config=make_config(), helper=helper)
        assert connector._author_opencti_id == connector.converter.author.id
        assert connector._author_opencti_id.startswith("identity--")
        # No extra API call to create an author identity.
        helper.api.identity.create.assert_not_called()


class TestCallback:
    def test_ping_failure_skips_import(self, helper):
        connector = build_connector(helper)
        connector.client.ping.side_effect = RuntimeError("no api")
        connector._import_data = MagicMock()
        connector._callback()
        connector._import_data.assert_not_called()

    def test_ping_ok_runs_import(self, helper):
        connector = build_connector(helper)
        connector._import_data = MagicMock()
        connector._callback()
        connector._import_data.assert_called_once()

    def test_keyboard_interrupt_propagates(self, helper):
        connector = build_connector(helper)
        connector._import_data = MagicMock(side_effect=KeyboardInterrupt())
        with pytest.raises(KeyboardInterrupt):
            connector._callback()

    def test_generic_error_is_swallowed(self, helper):
        connector = build_connector(helper)
        connector._import_data = MagicMock(side_effect=RuntimeError("boom"))
        connector._callback()  # must not raise
        helper.connector_logger.error.assert_called()


class TestRun:
    def test_schedule_and_tracker_stop(self, helper, monkeypatch):
        connector = build_connector(helper, enable_status_tracking=True)
        tracker_instance = MagicMock()
        monkeypatch.setattr(
            "connector.connector.CaseStatusTracker",
            MagicMock(return_value=tracker_instance),
        )
        connector.run()
        tracker_instance.start.assert_called_once()
        helper.schedule_process.assert_called_once()
        tracker_instance.stop.assert_called_once()  # stopped in finally


class TestImportData:
    def _wire(self, connector, with_objects=True):
        payload = [object()] if with_objects else []
        for getter in (
            "get_issues",
            "get_resolved_issues",
            "get_domain_assets",
            "get_host_assets",
            "get_ip_assets",
        ):
            getattr(connector.client, getter).return_value = []
        for conv in (
            "issues_to_stix",
            "resolved_issues_to_stix",
            "domain_assets_to_stix",
            "host_assets_to_stix",
            "ip_assets_to_stix",
        ):
            getattr(connector.converter, conv).return_value = list(payload)

    def test_happy_path_creates_work_and_sends(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {}
        self._wire(connector, with_objects=True)
        connector._import_data()
        helper.api.work.initiate_work.assert_called_once()
        helper.send_stix2_bundle.assert_called_once()
        helper.set_state.assert_called_once()
        # update=True must not be passed.
        assert "update" not in helper.send_stix2_bundle.call_args.kwargs

    def test_no_data_does_not_create_work(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {}
        self._wire(connector, with_objects=False)
        connector._import_data()
        helper.api.work.initiate_work.assert_not_called()
        helper.send_stix2_bundle.assert_not_called()
        helper.set_state.assert_called_once()

    def test_all_categories_fail_raises(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {}
        for getter in (
            "get_issues",
            "get_resolved_issues",
            "get_domain_assets",
            "get_host_assets",
            "get_ip_assets",
        ):
            getattr(connector.client, getter).side_effect = RuntimeError("down")
        with pytest.raises(ValueError, match="All 5 categories failed"):
            connector._import_data()
        helper.set_state.assert_not_called()

    def test_state_keys_preserved(self, helper):
        connector = build_connector(helper)
        helper.get_state.return_value = {
            "last_run": "old",
            "tracked_cases": {"HV-1": {"case_incident_id": "c1"}},
        }
        self._wire(connector, with_objects=True)
        connector._import_data()
        saved = helper.set_state.call_args[0][0]
        assert saved["tracked_cases"] == {"HV-1": {"case_incident_id": "c1"}}
        assert saved["last_run"] != "old"


class TestCreateCaseIncident:
    def _meta(self):
        return {
            "ticket_id": "HV-1",
            "name": "Issue [HV-1]",
            "description": "desc",
            "severity": "high",
            "priority": "P2",
            "created": "2026-03-04T18:00:00Z",
            "labels": ["ctm360-hackerview", "status:open"],
            "linked_stix_ids": ["vulnerability--x"],
            "response_types": ["exposure"],
            "hackerview_link": "https://hackerview.ctm360.com/issue/HV-1",
        }

    def test_empty_metadata_returns_zero(self, helper):
        connector = build_connector(helper)
        assert connector._create_case_incidents([]) == 0

    def test_create_case_incident_full(self, helper):
        helper.api.external_reference.create.return_value = {"id": "ext-1"}
        helper.api.case_incident.create.return_value = {"id": "case-1"}
        connector = build_connector(helper)
        connector._create_case_incident(self._meta())
        kwargs = helper.api.case_incident.create.call_args.kwargs
        assert kwargs["name"] == "Issue [HV-1]"
        assert kwargs["createdBy"] == connector._author_opencti_id
        assert kwargs["objects"] == ["vulnerability--x"]
        assert helper.api.stix_domain_object.add_label.call_count == 2
        helper.api.stix_domain_object.update_field.assert_called_once()

    def test_create_case_incidents_counts_errors(self, helper):
        helper.api.external_reference.create.return_value = {"id": "ext-1"}
        helper.api.case_incident.create.side_effect = [
            {"id": "case-1"},
            RuntimeError("boom"),
        ]
        connector = build_connector(helper)
        created = connector._create_case_incidents([self._meta(), self._meta()])
        assert created == 1
