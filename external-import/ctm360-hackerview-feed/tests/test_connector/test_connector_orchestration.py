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
    def test_author_identity_ships_in_bundle_not_via_api(self, helper):
        connector = CTM360HackerViewConnector(config=make_config(), helper=helper)
        # The author identity is created by the converter (deterministic id) and
        # shipped in the bundle — never created via an OpenCTI API call.
        assert connector.converter.author.id.startswith("identity--")
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


class TestCaseRegistration:
    """Cases ship in the bundle; the connector only registers them (no API create)."""

    def _wire_issue_cases(self, connector, meta):
        for getter in (
            "get_issues",
            "get_resolved_issues",
            "get_domain_assets",
            "get_host_assets",
            "get_ip_assets",
        ):
            getattr(connector.client, getter).return_value = []
        for conv in (
            "resolved_issues_to_stix",
            "domain_assets_to_stix",
            "host_assets_to_stix",
            "ip_assets_to_stix",
        ):
            getattr(connector.converter, conv).return_value = []

        def fake_issues_to_stix(_data):
            connector.converter.issue_case_metadata = meta
            return [object()]  # one case-incident object in the bundle

        connector.converter.issues_to_stix.side_effect = fake_issues_to_stix

    def test_cases_registered_from_metadata_without_api_create(self, helper):
        connector = build_connector(helper, enable_status_tracking=True)
        connector._tracker = MagicMock()
        helper.get_state.return_value = {}
        meta = [
            {
                "ticket_id": "HV-1",
                "case_incident_id": "case-incident--abc",
                "initial_status": "open",
            }
        ]
        self._wire_issue_cases(connector, meta)

        connector._import_data()

        # The case incident shipped in the bundle, not via the API.
        helper.api.case_incident.create.assert_not_called()
        helper.api.external_reference.create.assert_not_called()
        helper.send_stix2_bundle.assert_called_once()
        connector._tracker.register_cases.assert_called_once_with(meta)

    def test_no_tracker_still_no_api_create(self, helper):
        connector = build_connector(helper)  # tracking disabled, _tracker is None
        helper.get_state.return_value = {}
        meta = [
            {
                "ticket_id": "HV-1",
                "case_incident_id": "case-incident--abc",
                "initial_status": "open",
            }
        ]
        self._wire_issue_cases(connector, meta)

        connector._import_data()

        helper.api.case_incident.create.assert_not_called()
        helper.send_stix2_bundle.assert_called_once()

    def test_metadata_reset_prevents_stale_registration(self, helper):
        # A previous run left metadata on the converter; if issues are not
        # imported this cycle it must not be re-registered.
        connector = build_connector(helper, enable_status_tracking=True)
        connector._tracker = MagicMock()
        connector._import_issues = False
        connector.converter.issue_case_metadata = [{"ticket_id": "STALE"}]
        helper.get_state.return_value = {}
        for getter in (
            "get_resolved_issues",
            "get_domain_assets",
            "get_host_assets",
            "get_ip_assets",
        ):
            getattr(connector.client, getter).return_value = []
        for conv in (
            "resolved_issues_to_stix",
            "domain_assets_to_stix",
            "host_assets_to_stix",
            "ip_assets_to_stix",
        ):
            getattr(connector.converter, conv).return_value = []

        connector._import_data()

        connector._tracker.register_cases.assert_not_called()
