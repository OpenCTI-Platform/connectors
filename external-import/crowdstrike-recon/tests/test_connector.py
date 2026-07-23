from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings
from connector.connector import CrowdstrikeReconConnector


def _settings():
    settings_dict = {
        "opencti": {"url": "http://localhost:8080", "token": "test-token"},
        "connector": {
            "id": "connector-id",
            "name": "CrowdStrike Recon",
            "scope": "crowdstrike-recon",
            "log_level": "error",
            "duration_period": "PT1H",
        },
        "crowdstrike_recon": {
            "api_base_url": "https://api.crowdstrike.com",
            "client_id": "cid",
            "client_secret": "secret",
            "tlp_level": "amber+strict",
            "import_start_date": "P10D",
        },
    }

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    return FakeConnectorSettings()


def test_connector_init_builds_client_and_converter(monkeypatch):
    import crowdstrike_client.api_client as api_mod

    # Avoid constructing the real falconpy client (no network / credentials).
    monkeypatch.setattr(api_mod, "CrowdstrikeRecon", MagicMock())

    connector = CrowdstrikeReconConnector(config=_settings(), helper=MagicMock())

    assert connector.client is not None
    assert connector.converter_to_stix is not None


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


def test_collect_intelligence_ignores_unparseable_date():
    connector = _connector()
    connector.client.query_notifications.return_value = ["id1", "id2"]
    connector.client.get_notifications_details.return_value = [
        {"notification": {"created_date": "not-a-date"}},
        {"notification": {"created_date": "2026-05-02T00:00:00Z"}},
    ]
    connector.converter_to_stix.create_incident.return_value = ["entity"]

    _, most_recent = connector._collect_intelligence("2026-04-01T00:00:00Z")

    # The unparseable date is skipped; the valid one is kept.
    assert most_recent == "2026-05-02T00:00:00Z"


def test_process_message_uses_existing_state():
    connector = _connector()
    connector.helper.get_state.return_value = {
        "last_alert_date": "2026-04-01T00:00:00Z"
    }
    connector.helper.api.work.initiate_work.return_value = "work-1"
    connector.client.query_notifications.return_value = []
    connector.client.get_notifications_details.return_value = []

    connector.process_message()

    # The stored last_alert_date is used as the fetch cursor.
    connector.client.query_notifications.assert_called_once_with("2026-04-01T00:00:00Z")
    connector.helper.api.work.to_processed.assert_called_once()


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
