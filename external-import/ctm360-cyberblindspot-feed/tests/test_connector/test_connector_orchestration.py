"""Tests for the connector orchestration logic."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.connector import CTM360CyberBlindSpotConnector
from pydantic import SecretStr


def make_config(**overrides):
    cbs = SimpleNamespace(
        api_base_url="https://cbs.example.com",
        api_key=SecretStr("secret"),
        enable_status_tracking=False,
        import_interval=1,
        import_incidents=True,
        import_malware_logs=True,
        import_breached_credentials=True,
        import_card_leaks=True,
        import_domain_protection=True,
        status_poll_interval=3600,
    )
    for key, value in overrides.items():
        setattr(cbs, key, value)
    return SimpleNamespace(ctm360_cbs=cbs)


@pytest.fixture
def helper():
    helper = MagicMock()
    helper.api.work.initiate_work.return_value = "work-1"
    return helper


def build_connector(helper, **config_overrides):
    connector = CTM360CyberBlindSpotConnector(
        config=make_config(**config_overrides), helper=helper
    )
    connector.client = MagicMock()
    connector.converter = MagicMock()
    connector.converter.incident_case_metadata = []
    return connector


class TestResolveAuthorId:
    def test_success(self, helper):
        helper.api.identity.create.return_value = {"id": "identity--abc"}
        connector = build_connector(helper)
        assert connector._resolve_author_id() == "identity--abc"

    def test_none_result(self, helper):
        helper.api.identity.create.return_value = None
        connector = build_connector(helper)
        assert connector._resolve_author_id() == ""

    def test_exception(self, helper):
        helper.api.identity.create.side_effect = RuntimeError("api down")
        connector = build_connector(helper)
        assert connector._resolve_author_id() == ""
        helper.connector_logger.warning.assert_called()


class TestImportData:
    def _wire_converter(self, connector, returns_objects=True):
        payload = [object()] if returns_objects else []
        connector.client.get_incidents.return_value = []
        connector.client.get_malware_logs.return_value = []
        connector.client.get_breached_credentials.return_value = []
        connector.client.get_card_leaks.return_value = []
        connector.client.get_domain_protection.return_value = []
        connector.converter.incidents_to_stix.return_value = list(payload)
        connector.converter.malware_logs_to_stix.return_value = list(payload)
        connector.converter.breached_credentials_to_stix.return_value = list(payload)
        connector.converter.card_leaks_to_stix.return_value = list(payload)
        connector.converter.domain_protection_to_stix.return_value = list(payload)

    def test_happy_path_sends_bundle(self, helper):
        connector = build_connector(helper)
        self._wire_converter(connector, returns_objects=True)
        connector._import_data()
        helper.send_stix2_bundle.assert_called_once()
        helper.set_state.assert_called_once()
        assert helper.api.work.to_processed.call_args.kwargs.get("in_error") in (
            None,
            False,
        )

    def test_no_data(self, helper):
        connector = build_connector(helper)
        self._wire_converter(connector, returns_objects=False)
        connector._import_data()
        helper.send_stix2_bundle.assert_not_called()
        helper.set_state.assert_called_once()

    def test_partial_failure_still_succeeds(self, helper):
        connector = build_connector(helper)
        self._wire_converter(connector, returns_objects=True)
        connector.client.get_malware_logs.side_effect = RuntimeError("endpoint down")
        connector._import_data()
        helper.send_stix2_bundle.assert_called_once()
        helper.set_state.assert_called_once()

    def test_all_categories_fail_raises(self, helper):
        connector = build_connector(helper)
        for getter in (
            "get_incidents",
            "get_malware_logs",
            "get_breached_credentials",
            "get_card_leaks",
            "get_domain_protection",
        ):
            getattr(connector.client, getter).side_effect = RuntimeError("down")
        with pytest.raises(ValueError, match="All 5 categories failed"):
            connector._import_data()
        # Work was marked errored, state was NOT advanced.
        helper.set_state.assert_not_called()

    def test_state_keys_are_preserved(self, helper):
        connector = build_connector(helper)
        self._wire_converter(connector, returns_objects=True)
        helper.get_state.return_value = {
            "last_run": "old",
            "tracked_cases": {"T1": {"case_incident_id": "c1"}},
        }
        connector._import_data()
        saved = helper.set_state.call_args[0][0]
        assert saved["tracked_cases"] == {"T1": {"case_incident_id": "c1"}}
        assert saved["last_run"] != "old"

    def test_duplicate_objects_are_deduplicated_before_bundling(self, helper):
        # Every category converter prepends the shared author Identity, so the
        # concatenated output repeats it; the bundle must carry it only once.
        connector = build_connector(helper)
        author = SimpleNamespace(id="identity--author")
        connector.client.get_incidents.return_value = []
        connector.client.get_malware_logs.return_value = []
        connector.client.get_breached_credentials.return_value = []
        connector.client.get_card_leaks.return_value = []
        connector.client.get_domain_protection.return_value = []
        connector.converter.incidents_to_stix.return_value = [author]
        connector.converter.malware_logs_to_stix.return_value = [
            author,
            SimpleNamespace(id="malware--1"),
        ]
        connector.converter.breached_credentials_to_stix.return_value = [author]
        connector.converter.card_leaks_to_stix.return_value = [author]
        connector.converter.domain_protection_to_stix.return_value = [author]

        connector._import_data()

        bundled = helper.stix2_create_bundle.call_args[0][0]
        ids = [obj.id for obj in bundled]
        assert ids.count("identity--author") == 1
        assert "malware--1" in ids

    def test_author_only_bundle_is_not_sent(self, helper):
        # Every converter prepends the shared author Identity, so a cycle where
        # all endpoints returned no data still yields an author-only list. That
        # must be treated as "no data" and skip the bundle rather than shipping
        # an author-only work item every cycle.
        connector = build_connector(helper)
        author = SimpleNamespace(id="identity--author")
        connector.converter.author = author
        connector.client.get_incidents.return_value = []
        connector.client.get_malware_logs.return_value = []
        connector.client.get_breached_credentials.return_value = []
        connector.client.get_card_leaks.return_value = []
        connector.client.get_domain_protection.return_value = []
        connector.converter.incidents_to_stix.return_value = [author]
        connector.converter.malware_logs_to_stix.return_value = [author]
        connector.converter.breached_credentials_to_stix.return_value = [author]
        connector.converter.card_leaks_to_stix.return_value = [author]
        connector.converter.domain_protection_to_stix.return_value = [author]

        connector._import_data()

        helper.send_stix2_bundle.assert_not_called()
        # State still advances even when there is no data to import.
        helper.set_state.assert_called_once()
        assert helper.api.work.to_processed.call_args.args[1] == "No new data to import"

    def test_disabled_categories_are_skipped(self, helper):
        connector = build_connector(
            helper,
            import_malware_logs=False,
            import_breached_credentials=False,
            import_card_leaks=False,
            import_domain_protection=False,
        )
        self._wire_converter(connector, returns_objects=True)
        connector._import_data()
        connector.client.get_incidents.assert_called_once()
        connector.client.get_malware_logs.assert_not_called()


class TestCreateCaseIncidents:
    def _meta(self, **overrides):
        meta = {
            "ticket_id": "INC-1",
            "name": "Phishing [INC-1]",
            "description": "desc",
            "severity": "high",
            "priority": "P2",
            "created": "2026-03-04T18:00:00Z",
            "labels": ["phishing", "ctm360-cbs"],
            "response_types": ["Phishing"],
        }
        meta.update(overrides)
        return meta

    def test_empty_metadata_returns_zero(self, helper):
        connector = build_connector(helper)
        assert connector._create_case_incidents([]) == 0

    def test_create_case_incident_full(self, helper):
        helper.api.external_reference.create.return_value = {"id": "ext-1"}
        helper.api.case_incident.create.return_value = {"id": "case-1"}
        connector = build_connector(helper)
        connector._author_opencti_id = "identity--author"
        connector._create_case_incident(self._meta())

        kwargs = helper.api.case_incident.create.call_args.kwargs
        assert kwargs["name"] == "Phishing [INC-1]"
        assert kwargs["createdBy"] == "identity--author"
        assert kwargs["externalReferences"] == ["ext-1"]
        assert helper.api.stix_domain_object.add_label.call_count == 2
        helper.api.stix_domain_object.update_field.assert_called_once()

    def test_create_case_incident_registers_with_tracker(self, helper):
        helper.api.external_reference.create.return_value = {"id": "ext-1"}
        helper.api.case_incident.create.return_value = {"id": "case-1"}
        connector = build_connector(helper)
        connector._tracker = MagicMock()
        connector._create_case_incident(self._meta(response_types=[]))
        connector._tracker.register_case.assert_called_once()
        helper.api.stix_domain_object.update_field.assert_not_called()

    def test_create_case_incidents_counts_and_handles_errors(self, helper):
        helper.api.external_reference.create.return_value = {"id": "ext-1"}
        helper.api.case_incident.create.side_effect = [
            {"id": "case-1"},
            RuntimeError("boom"),
        ]
        connector = build_connector(helper)
        created = connector._create_case_incidents(
            [self._meta(ticket_id="INC-1"), self._meta(ticket_id="INC-2")]
        )
        assert created == 1


class TestRun:
    def test_ping_failure_exits(self, helper):
        connector = build_connector(helper)
        connector.client.ping.side_effect = RuntimeError("no api")
        with pytest.raises(SystemExit):
            connector.run()

    def test_run_loop_breaks_on_keyboard_interrupt(self, helper, monkeypatch):
        helper.api.identity.create.return_value = {"id": "identity--a"}
        connector = build_connector(helper)
        monkeypatch.setattr("connector.connector.time.sleep", lambda *_: None)
        connector._import_data = MagicMock(side_effect=KeyboardInterrupt())
        connector.run()
        connector._import_data.assert_called_once()

    def test_run_starts_tracker_when_enabled(self, helper, monkeypatch):
        helper.api.identity.create.return_value = {"id": "identity--a"}
        connector = build_connector(helper, enable_status_tracking=True)
        tracker_instance = MagicMock()
        monkeypatch.setattr(
            "connector.connector.CaseStatusTracker",
            MagicMock(return_value=tracker_instance),
        )
        monkeypatch.setattr("connector.connector.time.sleep", lambda *_: None)
        connector._import_data = MagicMock(side_effect=KeyboardInterrupt())
        connector.run()
        tracker_instance.start.assert_called_once()

    def test_run_continues_on_import_error(self, helper, monkeypatch):
        helper.api.identity.create.return_value = {"id": "identity--a"}
        connector = build_connector(helper)
        monkeypatch.setattr("connector.connector.time.sleep", lambda *_: None)
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            raise KeyboardInterrupt()

        connector._import_data = MagicMock(side_effect=flaky)
        connector.run()
        assert calls["n"] == 2
