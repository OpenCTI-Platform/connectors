from datetime import datetime, timezone
from unittest.mock import MagicMock, call, patch

from rflib.pyrf import Alert, PrioritiedRule, RecordedFutureApiClient
from rflib.rf_alerts import RecordedFutureAlertConnector

_RULE = PrioritiedRule(
    rule_id="rule-1",
    rule_name="Test Rule",
    rule_intelligence_goal="Test Goal",
)


def _make_alert(alert_id, alert_date="2025-01-01T00:00:00Z"):
    """Create a minimal Alert object for testing."""
    return Alert(
        alert_id=alert_id,
        alert_url="https://example.com",
        alert_date=alert_date,
        alert_title=f"Alert {alert_id}",
        alert_ai_insight="insight",
        alert_rf_rule=_RULE,
        alert_hits=[],
    )


def _build_connector(helper):
    """Build a connector instance with mocked internals."""
    rf_api = MagicMock()
    with patch.object(
        RecordedFutureAlertConnector, "__init__", lambda self, *a, **kw: None
    ):
        connector = RecordedFutureAlertConnector.__new__(RecordedFutureAlertConnector)
        connector.helper = helper
        connector.work_id = "work-1"
        connector.api_recorded_future = rf_api
        connector.opencti_default_severity = "low"
        connector.tlp = None
        connector.author = MagicMock()
        connector.update_rules = MagicMock()
        connector.alert_to_incident = MagicMock()
    return connector


def test_set_state_called_for_each_alert():
    """set_state must be called once per successfully processed alert."""
    # Given: 3 alerts to process
    helper = MagicMock()
    helper.get_state.return_value = {}
    helper.connect_name = "RecordedFuture"
    helper.connector_id = "connector-1"

    connector = _build_connector(helper)
    alerts = [_make_alert("a1"), _make_alert("a2"), _make_alert("a3")]
    connector.collect_alerts = MagicMock(return_value=alerts)

    # When: the connector runs
    connector.run()

    # Then: set_state is called once per alert
    assert helper.set_state.call_count == len(alerts)


def test_set_state_uses_alert_date():
    """set_state should persist each alert's date as last_processed_alert_date."""
    # Given: 2 alerts with distinct dates
    helper = MagicMock()
    helper.get_state.return_value = {}
    helper.connect_name = "RecordedFuture"
    helper.connector_id = "connector-1"

    connector = _build_connector(helper)
    alerts = [
        _make_alert("a1", alert_date="2025-06-01T10:00:00Z"),
        _make_alert("a2", alert_date="2025-06-02T12:00:00Z"),
    ]
    connector.collect_alerts = MagicMock(return_value=alerts)

    # When: the connector runs
    connector.run()

    # Then: each set_state call saves the alert's own date
    helper.set_state.assert_has_calls(
        [
            call({"last_processed_alert_date": "2025-06-01T10:00:00"}),
            call({"last_processed_alert_date": "2025-06-02T12:00:00"}),
        ]
    )


def test_migrates_old_state_key():
    """Old last_alerts_run key should be migrated to last_processed_alert_date."""
    # Given: state contains the old key name
    helper = MagicMock()
    helper.get_state.return_value = {"last_alerts_run": "2025-06-01T10:00:00"}
    helper.connect_name = "RecordedFuture"
    helper.connector_id = "connector-1"

    connector = _build_connector(helper)
    connector.collect_alerts = MagicMock(return_value=[])

    # When: the connector runs
    connector.run()

    # Then: old key is removed and value is migrated to the new key
    migration_call = helper.set_state.call_args_list[0]
    saved_state = migration_call.args[0]
    assert "last_alerts_run" not in saved_state
    assert saved_state["last_processed_alert_date"] == "2025-06-01T10:00:00"


def test_alerts_processed_in_chronological_order():
    """Alerts must be sorted by date before processing, even if collected out of order."""
    # Given: alerts collected in reverse chronological order
    helper = MagicMock()
    helper.get_state.return_value = {}
    helper.connect_name = "RecordedFuture"
    helper.connector_id = "connector-1"

    connector = _build_connector(helper)
    alerts = [
        _make_alert("a3", alert_date="2025-06-10T00:00:00Z"),
        _make_alert("a1", alert_date="2025-06-01T00:00:00Z"),
        _make_alert("a2", alert_date="2025-06-05T00:00:00Z"),
    ]
    connector.collect_alerts = MagicMock(return_value=alerts)

    # When: the connector runs
    connector.run()

    # Then: alerts are processed oldest-first
    processed_ids = [
        c.args[0].alert_id for c in connector.alert_to_incident.call_args_list
    ]
    assert processed_ids == ["a1", "a2", "a3"]


def test_raw_get_alerts_sends_sort_params():
    """_raw_get_alerts must request alerts sorted by triggered date ascending."""
    # Given: a Recorded Future API client
    helper = MagicMock()
    rule = PrioritiedRule(
        rule_id="rule-1",
        rule_name="Test Rule",
        rule_intelligence_goal="Test Goal",
    )

    client = RecordedFutureApiClient.__new__(RecordedFutureApiClient)
    client.x_rf_token = "fake-token"
    client.base_url = "https://api.recordedfuture.com/"
    client.helper = helper

    fake_response = MagicMock()
    fake_response.json.return_value = {"data": [], "counts": {"total": 0}}

    # When: _raw_get_alerts is called
    with patch("rflib.pyrf.requests.get", return_value=fake_response) as mock_get:
        client._raw_get_alerts(
            rule=rule,
            triggered_since=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )

        # Then: request includes orderby=triggered and direction=asc
        params = mock_get.call_args.kwargs["params"]
        assert params["orderby"] == "triggered"
        assert params["direction"] == "asc"
