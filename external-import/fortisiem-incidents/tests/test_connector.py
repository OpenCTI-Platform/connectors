from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from connector.connector import FortiSIEMIncidentsConnector
from fortisiem_client import FortiSIEMClientError


def _make_connector():
    helper = MagicMock()
    with patch("connector.connector.FortiSIEMClient") as client_cls:
        connector = FortiSIEMIncidentsConnector(config=MagicMock(), helper=helper)
    connector.client = client_cls.return_value
    return connector, helper, connector.client


def test_collect_intelligence_builds_objects():
    connector, _, client = _make_connector()
    client.get_incidents.return_value = [
        {"incidentTitle": "Bad", "incidentId": 1, "srcIpAddr": "198.51.100.1"}
    ]

    objects = connector._collect_intelligence("2026-01-01T00:00:00Z")
    types = [o["type"] for o in objects]

    assert "incident" in types
    assert "ipv4-addr" in types
    assert "relationship" in types
    assert "identity" in types  # author appended


def test_collect_intelligence_empty():
    connector, _, client = _make_connector()
    client.get_incidents.return_value = []

    assert connector._collect_intelligence("since") == []


def test_since_uses_last_run():
    connector, _, _ = _make_connector()
    assert (
        connector._since({"last_run": "2026-01-01T00:00:00Z"}) == "2026-01-01T00:00:00Z"
    )


def test_since_uses_window():
    connector, _, _ = _make_connector()
    connector.config = SimpleNamespace(
        fortisiem_incidents=SimpleNamespace(import_window_days=7)
    )
    assert "T" in connector._since({})


def test_process_message_sends_bundle():
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {"last_run": "2026-01-01T00:00:00Z"}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.stix2_create_bundle.return_value = "bundle"
    client.get_incidents.return_value = [
        {"incidentTitle": "Bad", "incidentId": 1, "srcIpAddr": "198.51.100.1"}
    ]

    connector.process_message()

    helper.send_stix2_bundle.assert_called_once()
    helper.set_state.assert_called_once()
    helper.api.work.to_processed.assert_called_once()


def test_process_message_handles_errors():
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {"last_run": "2026-01-01T00:00:00Z"}
    helper.api.work.initiate_work.return_value = "work-1"
    client.get_incidents.side_effect = RuntimeError("boom")

    connector.process_message()  # must not raise

    helper.connector_logger.error.assert_called()


def test_process_message_does_not_advance_state_on_fetch_failure():
    # A fetch failure must not advance last_run (otherwise a transient outage would
    # silently skip incidents). Since the work is only initiated once data has been
    # fetched, no (empty) work is created or finalized on the failure path.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {"last_run": "2026-01-01T00:00:00Z"}
    client.get_incidents.side_effect = FortiSIEMClientError("down")

    connector.process_message()  # must not raise

    helper.set_state.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.api.work.initiate_work.assert_not_called()
    helper.api.work.to_processed.assert_not_called()


def test_process_message_finalizes_work_in_error_on_send_failure():
    # If the bundle send fails after the work was initiated, the work must be
    # finalized with in_error=True instead of dangling, and last_run must not
    # advance.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {"last_run": "2026-01-01T00:00:00Z"}
    helper.api.work.initiate_work.return_value = "work-1"
    helper.send_stix2_bundle.side_effect = RuntimeError("send failed")
    client.get_incidents.return_value = [
        {"incidentTitle": "Bad", "incidentId": 1, "srcIpAddr": "198.51.100.1"}
    ]

    connector.process_message()  # must not raise

    helper.set_state.assert_not_called()
    helper.api.work.to_processed.assert_called_once()
    assert helper.api.work.to_processed.call_args.kwargs["in_error"] is True


def test_process_message_no_incidents_creates_no_work():
    # No new incidents -> no work initiated (no empty jobs), but the state still
    # advances because the window was fetched successfully.
    connector, helper, client = _make_connector()
    helper.get_state.return_value = {"last_run": "2026-01-01T00:00:00Z"}
    client.get_incidents.return_value = []

    connector.process_message()

    helper.api.work.initiate_work.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()
    helper.set_state.assert_called_once()


def test_run_schedules_process():
    connector, helper, _ = _make_connector()

    connector.run()

    helper.schedule_process.assert_called_once()
