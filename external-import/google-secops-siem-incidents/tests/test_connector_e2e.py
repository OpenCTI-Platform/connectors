"""End-to-end tests for the full A-to-Z connector run using stubs and caplog log-assertion fixtures."""

import logging
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from google_secops_siem_incidents.connector import GoogleSecOpsConnector
from google_secops_siem_incidents.models.rule_alert_response import RuleAlertResponse
from google_secops_siem_incidents.utils.enums import Priority, Severity
from pycti import OpenCTIConnectorHelper
from tests_converter_stix.factories import (
    AlertFactory,
    AlertFieldFactory,
    RuleAlertFactory,
    RuleAlertResponseFactory,
    RuleMetadataFactory,
    RulePropertiesFactory,
    make_hostname_outcomes,
    make_ip_outcomes,
    make_multi_hostname_outcomes,
    make_risk_score_outcome,
)

# =====================
# Fixtures
# =====================


@pytest.fixture
def two_batches() -> list[RuleAlertResponse]:
    """Two RuleAlertResponse batches with distinct detection timestamps."""
    return [
        _build_batch("2024-03-01T10:00:00Z"),
        _build_batch("2024-03-01T11:00:00Z"),
    ]


@pytest.fixture
def expected_full_run_log_messages() -> list[str]:
    """Return expected structured log messages for a full 2-batch first run without pagination."""
    return [
        "[CONNECTOR] Run started - {'start_time':",
        "[CONNECTOR] Batch fetched - {'batch_num': 1, 'rule_alerts': 1, 'alerts': 2}",
        (
            "[CONNECTOR] Batch converted to STIX - {'batch_num': 1, 'stix_count': '18 (~14 unique)',"
            " 'type_summary': 'hostname: 3, incident: 2, ipv4-addr: 5 (~3 unique), relationship: 8 (~6 unique)'}"
        ),
        (
            "[CONNECTOR] Bundle sent - {'batch_num': 1, 'work_id': 'work-id-123',"
            " 'stix_count': '20 (~16 unique)',"
            " 'type_summary': 'hostname: 3, identity: 1, incident: 2, ipv4-addr: 5 (~3 unique), marking-definition: 1, relationship: 8 (~6 unique)'}"
        ),
        "[CONNECTOR] Batch fetched - {'batch_num': 2, 'rule_alerts': 1, 'alerts': 2}",
        (
            "[CONNECTOR] Batch converted to STIX - {'batch_num': 2, 'stix_count': '18 (~14 unique)',"
            " 'type_summary': 'hostname: 3, incident: 2, ipv4-addr: 5 (~3 unique), relationship: 8 (~6 unique)'}"
        ),
        (
            "[CONNECTOR] Bundle sent - {'batch_num': 2, 'work_id': 'work-id-123',"
            " 'stix_count': '20 (~16 unique)',"
            " 'type_summary': 'hostname: 3, identity: 1, incident: 2, ipv4-addr: 5 (~3 unique), marking-definition: 1, relationship: 8 (~6 unique)'}"
        ),
        "[CONNECTOR] State updated - {'total_batches': 2, 'last_alert_timestamp':",
        "[CONNECTOR] Run completed - {'total_batches': 2, 'total_alerts': 4, 'total_stix_objects': '36 (~22 unique)',",
    ]


@pytest.fixture
def expected_resume_run_log_messages() -> list[str]:
    """Expected log messages when resuming from a saved state (not a first run)."""
    return [
        "[CONNECTOR] Run started - {'start_time': '2024-03-01T12:00:00+00:00',",
        "[CONNECTOR] Batch fetched - {'batch_num': 1, 'rule_alerts': 1, 'alerts': 2}",
        "[CONNECTOR] Batch fetched - {'batch_num': 2, 'rule_alerts': 1, 'alerts': 2}",
        "[CONNECTOR] Run completed - {'total_batches': 2, 'total_alerts': 4, 'total_stix_objects': '36 (~22 unique)',",
    ]


# =====================
# Scenarios
# =====================


# Scenario: Full 2-batch connector run from scratch
def test_full_two_batch_run(
    two_batches: list[RuleAlertResponse],
    expected_full_run_log_messages: list[str],
    caplog: Any,
) -> None:
    """Verify all structured log messages and counts for a full 2-batch first run with no prior state."""
    # _given_ a fresh connector with two non-paginated batches and no prior state
    connector = _given_connector_with_stubs(two_batches)

    # _when_ process_message() is called with log capture
    _when_process_message_runs(connector, caplog)

    # _then_ every expected structured log message appears in caplog
    _then_run_completed_successfully(caplog, expected_full_run_log_messages)


# Scenario: Connector resumes from a previously saved state
def test_resumes_from_saved_state(
    two_batches: list[RuleAlertResponse],
    expected_resume_run_log_messages: list[str],
    caplog: Any,
) -> None:
    """Verify that a saved last_alert_timestamp is used as start_time on resume and the run completes correctly."""
    # _given_ a connector with a prior saved last_alert_timestamp of 2024-03-01T12:00:00+00:00
    saved_state = {"last_alert_timestamp": "2024-03-01T12:00:00+00:00"}
    connector = _given_connector_with_stubs(two_batches, saved_state=saved_state)

    # _when_ process_message() is called with log capture
    _when_process_message_runs(connector, caplog)

    # _then_ every expected resume log message appears in caplog
    _then_run_completed_successfully(caplog, expected_resume_run_log_messages)


# Scenario: State is persisted with max detection_timestamp (per-batch checkpoint)
def test_state_persisted_with_correct_timestamp(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that final state has max detection_ts and no pagination_checkpoint for non-paginated runs."""
    # _given_ a connector with two non-paginated batches tracked via spy helper
    helper = _make_mock_helper()
    connector = _given_connector_with_stubs(two_batches, helper=helper)

    # _when_ process_message() runs with log capture
    _when_process_message_runs(connector, caplog)

    # _then_ — per-batch checkpoint with global max timestamp
    all_state_calls = [c[0][0] for c in helper.set_state.call_args_list]
    checkpoint_timestamps = [
        c["last_alert_timestamp"]
        for c in all_state_calls
        if "last_alert_timestamp" in c
    ]
    assert any(
        "2024-03-01T11:00:01" in ts for ts in checkpoint_timestamps
    ), f"Expected checkpoint with 11:00:01 (+1s offset), got: {checkpoint_timestamps}"

    # _then_ — final state carries max detection_ts + 1s from the run
    final_state = all_state_calls[-1]
    assert "last_alert_timestamp" in final_state
    assert "2024-03-01T11:00:01" in final_state["last_alert_timestamp"], (
        f"Final state should be max detection_ts + 1s from run data,"
        f" got: {final_state['last_alert_timestamp']}"
    )
    assert (
        final_state.get("pagination_checkpoint") is None
    ), "pagination_checkpoint must be cleared after a clean run"


# =====================
# GWT helpers
# =====================


def _given_connector_with_stubs(
    batches: list[RuleAlertResponse],
    *,
    helper: Any = None,
    saved_state: dict | None = None,
    config: Any = None,
) -> GoogleSecOpsConnector:
    """Set up a GoogleSecOpsConnector with a stubbed Chronicle client."""
    if helper is None:
        helper = _make_mock_helper(initial_state=saved_state)

    if config is None:
        config = _make_mock_config()
    connector = GoogleSecOpsConnector(config=config, helper=helper)

    async def _stub_fetch(*args: Any, **kwargs: Any):
        for batch in batches:
            yield batch

    connector.client = MagicMock()
    connector.client.fetch_rule_alerts = _stub_fetch
    connector.client.close = AsyncMock()

    return connector


def _when_process_message_runs(connector: GoogleSecOpsConnector, caplog: Any) -> None:
    """Execute the connector's process_message, capturing logs."""
    with caplog.at_level(logging.INFO):
        connector.process_message()


def _then_run_completed_successfully(
    caplog: Any, expected_log_messages: list[str]
) -> None:
    """Assert that every expected log message appears in the captured log output."""
    all_messages = [rec.getMessage() for rec in caplog.records]
    missing = [
        msg
        for msg in expected_log_messages
        if not any(msg in log_msg for log_msg in all_messages)
    ]
    assert not missing, "Missing expected log messages:\n" + "\n".join(
        f"  \u2717 {m}" for m in missing
    )


class _MetaLogger:
    """pycti-AppLogger-like logger for tests.

    Mirrors ``OpenCTIConnectorHelper.connector_logger``: every method takes
    ``(message, meta=None)`` and, when meta is provided, merges it into the
    emitted record so ``caplog`` assertions can match on the structured fields.
    """

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def _emit(self, level: int, message: str, meta: dict | None) -> None:
        if meta:
            self._logger.log(level, "%s - %s", message, meta)
        else:
            self._logger.log(level, message)

    def debug(self, message: str, meta: dict | None = None) -> None:
        self._emit(logging.DEBUG, message, meta)

    def info(self, message: str, meta: dict | None = None) -> None:
        self._emit(logging.INFO, message, meta)

    def warning(self, message: str, meta: dict | None = None) -> None:
        self._emit(logging.WARNING, message, meta)

    def error(self, message: str, meta: dict | None = None) -> None:
        self._emit(logging.ERROR, message, meta)


def _make_mock_helper(initial_state: dict | None = None) -> MagicMock:
    """Build a fully mocked OpenCTIConnectorHelper with stateful get/set_state using full-replacement semantics."""
    helper = MagicMock(spec=OpenCTIConnectorHelper)
    helper.connect_name = "Google SecOps"
    helper.connect_id = "test-connector-id"

    _state: dict = dict(initial_state or {})
    helper.get_state.side_effect = lambda: dict(_state) if _state else {}

    def _set_state(s: dict) -> None:
        _state.clear()
        _state.update(s)

    helper.set_state.side_effect = _set_state

    helper.force_ping = MagicMock()
    helper.api = MagicMock()
    helper.api.work.initiate_work.return_value = "work-id-123"
    helper.stix2_create_bundle.side_effect = lambda objs: {"objects": objs}
    helper.send_stix2_bundle.return_value = None
    helper.connector_logger = _MetaLogger("test_connector_e2e")
    return helper


def _make_mock_config() -> MagicMock:
    """Build a minimal ConnectorSettings mock."""
    config = MagicMock()
    config.google_secops_siem_incidents.tlp_level = "amber"
    config.google_secops_siem_incidents.first_start_time = timedelta(hours=1)
    config.google_secops_siem_incidents.severity_filter = None
    config.google_secops_siem_incidents.priority_filter = None
    config.google_secops_siem_incidents.risk_score_filter = None
    config.google_secops_siem_incidents.tags_include = None
    config.google_secops_siem_incidents.tags_exclude = None
    return config


# =====================
# Stub builders
# =====================


def _build_batch(
    detection_ts: str,
    severity: str = "MEDIUM",
    priority: str = "MEDIUM",
) -> RuleAlertResponse:
    """Build a RuleAlertResponse with 2 alerts sharing the same detection_timestamp."""
    alert1 = AlertFactory.build(
        fields=[AlertFieldFactory.build(name="ip", string_val="10.0.0.1")],
        outcomes=make_multi_hostname_outcomes(["host1a.local", "host1b.local"])
        + make_ip_outcomes(["10.0.0.1", "10.0.0.2"]),
        detection_timestamp=detection_ts,
    )
    alert2 = AlertFactory.build(
        fields=[AlertFieldFactory.build(name="ip", string_val="10.0.0.3")],
        outcomes=make_hostname_outcomes("host2.local") + make_ip_outcomes(["10.0.0.3"]),
        detection_timestamp=detection_ts,
    )
    rule_alert = RuleAlertFactory.build(
        alerts=[alert1, alert2],
        rule_metadata=RuleMetadataFactory.build(
            properties=RulePropertiesFactory.build(
                metadata={
                    "severity": severity,
                    "priority": priority,
                    "tags": "test",
                },
            ),
        ),
    )
    return RuleAlertResponseFactory.build(rule_alerts=[rule_alert])


def _build_paginated_batch(detection_ts: str) -> RuleAlertResponse:
    """Build a RuleAlertResponse with ``too_many_alerts=True`` (pagination trigger)."""
    alert1 = AlertFactory.build(
        fields=[AlertFieldFactory.build(name="ip", string_val="10.0.0.1")],
        outcomes=make_hostname_outcomes("host1.local") + make_ip_outcomes(["10.0.0.1"]),
        detection_timestamp=detection_ts,
    )
    alert2 = AlertFactory.build(
        fields=[AlertFieldFactory.build(name="ip", string_val="10.0.0.2")],
        outcomes=make_hostname_outcomes("host2.local") + make_ip_outcomes(["10.0.0.2"]),
        detection_timestamp=detection_ts,
    )
    rule_alert = RuleAlertFactory.build(
        alerts=[alert1, alert2],
        rule_metadata=RuleMetadataFactory.build(
            properties=RulePropertiesFactory.build(
                metadata={
                    "severity": "MEDIUM",
                    "priority": "MEDIUM",
                    "tags": "test",
                },
            ),
        ),
    )
    return RuleAlertResponseFactory.build(
        rule_alerts=[rule_alert], too_many_alerts=True
    )


# =====================
# Fixtures — paginated run
# =====================


@pytest.fixture
def paginated_two_batches() -> list[RuleAlertResponse]:
    """Two batches simulating backward pagination: batch 1 triggers too_many_alerts=True, batch 2 terminates cleanly."""
    return [
        _build_paginated_batch("2024-03-01T10:00:00Z"),
        _build_batch("2024-03-01T09:00:00Z"),
    ]


# =====================
# Scenarios — pagination checkpoint
# =====================


# Scenario: pagination checkpoint written and cleared on completion
def test_pagination_checkpoint_written_and_cleared(
    paginated_two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify pagination_checkpoint is written after too_many_alerts=True and cleared on clean completion."""
    helper = _make_mock_helper()
    connector = _given_connector_with_stubs(paginated_two_batches, helper=helper)
    _when_process_message_runs(connector, caplog)

    all_state_calls = [c[0][0] for c in helper.set_state.call_args_list]

    # checkpoint written after batch 1
    checkpoint_calls = [c for c in all_state_calls if "pagination_checkpoint" in c]
    assert (
        len(checkpoint_calls) >= 1
    ), "Expected at least one pagination_checkpoint write"
    cp = checkpoint_calls[0]["pagination_checkpoint"]
    assert "window_start" in cp
    assert cp["window_end"] == "2024-03-01T10:00:00+00:00"
    assert cp["run_max_ts"] == "2024-03-01T10:00:00+00:00"

    # final state: checkpoint cleared, last_alert_timestamp set to batch 1 max (10:00 > 09:00)
    final_state = all_state_calls[-1]
    assert (
        final_state.get("pagination_checkpoint") is None
    ), "pagination_checkpoint must be cleared after a clean run"
    assert "2024-03-01T10:00:01" in final_state["last_alert_timestamp"]


# Scenario: log emitted for pagination checkpoint and not for plain batches
def test_pagination_checkpoint_log_emitted(
    paginated_two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """State checkpoint log only appears for batches with too_many_alerts=True."""
    connector = _given_connector_with_stubs(paginated_two_batches)
    _when_process_message_runs(connector, caplog)

    all_messages = [rec.getMessage() for rec in caplog.records]
    checkpoint_logs = [m for m in all_messages if "State checkpoint" in m]

    # exactly one checkpoint log (batch 1 only; batch 2 has too_many_alerts=False)
    assert len(checkpoint_logs) == 1
    assert "window_end" in checkpoint_logs[0]
    assert "run_max_ts" in checkpoint_logs[0]
    # batch 2 must NOT have emitted a checkpoint
    assert "batch_num': 2" not in checkpoint_logs[0]


# Scenario: connector resumes from a pagination checkpoint
def test_resumes_from_pagination_checkpoint(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that a saved pagination_checkpoint resumes backward-pagination from the correct window bounds."""
    checkpoint_state = {
        "pagination_checkpoint": {
            "window_start": "2024-03-01T08:00:00+00:00",
            "window_end": "2024-03-01T10:00:00+00:00",
            "run_max_ts": "2024-03-01T11:00:00+00:00",
        }
    }
    helper = _make_mock_helper(initial_state=checkpoint_state)
    connector = _given_connector_with_stubs(two_batches, helper=helper)
    _when_process_message_runs(connector, caplog)

    # log must show the resumed window, not a fresh now-based end_time
    all_messages = [rec.getMessage() for rec in caplog.records]
    run_started = next(m for m in all_messages if "Run started" in m)
    assert "2024-03-01T08:00:00+00:00" in run_started
    assert "2024-03-01T10:00:00+00:00" in run_started
    assert "resumed': True" in run_started

    # final state: checkpoint cleared, last_alert_timestamp = max(11:00, 10:00, 11:00) + 1s
    all_state_calls = [c[0][0] for c in helper.set_state.call_args_list]
    final_state = all_state_calls[-1]
    assert final_state.get("pagination_checkpoint") is None
    assert "2024-03-01T11:00:01" in final_state["last_alert_timestamp"]


# =====================
# Scenario — S-05: first run uses state.save() (force_ping called)
# =====================


def test_first_run_calls_force_ping_via_state_save(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """S-05: Verify state is written via state.save() (which calls force_ping) and not raw set_state."""
    # _given_ a fresh connector with two non-paginated batches tracked via spy helper
    helper = _make_mock_helper()
    connector = _given_connector_with_stubs(two_batches, helper=helper)

    # _when_ process_message() runs with log capture
    _when_process_message_runs(connector, caplog)

    # _then_ — force_ping must have been called at least once (by state.save())
    assert helper.force_ping.called, (  # noqa: S101
        "Expected helper.force_ping() to be called via state.save(), "
        "but it was never called — connector likely uses raw set_state()"
    )


# =====================
# Scenarios — severity filter
# =====================


def test_severity_filter_excludes_below_threshold(
    caplog: Any,
) -> None:
    """Verify that alerts below the severity threshold are excluded from STIX conversion."""
    # _given_ a batch with severity "MEDIUM" and a threshold of HIGH
    batches = [_build_batch("2024-03-01T10:00:00Z")]
    config = _make_mock_config()
    config.google_secops_siem_incidents.severity_filter = Severity.HIGH
    connector = _given_connector_with_stubs(batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ no bundle should be sent (medium < high threshold)
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert not any(
        "Bundle sent" in m for m in all_messages
    ), "Expected no bundle to be sent when severity is below threshold"


def test_severity_filter_includes_at_threshold(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that alerts at the severity threshold are imported."""
    # _given_ a threshold of MEDIUM (matching the test batch severity)
    config = _make_mock_config()
    config.google_secops_siem_incidents.severity_filter = Severity.MEDIUM
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent normally
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when severity meets threshold"


def test_severity_filter_includes_above_threshold(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that alerts above the severity threshold are imported."""
    # _given_ a threshold of LOW (medium > low)
    config = _make_mock_config()
    config.google_secops_siem_incidents.severity_filter = Severity.LOW
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when severity is above threshold"


def test_severity_filter_none_imports_all(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that None severity filter imports all alerts regardless of severity."""
    # _given_ no severity filter (default behavior)
    config = _make_mock_config()
    config.google_secops_siem_incidents.severity_filter = None
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent (all alerts imported)
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when severity filter is None (all pass)"


# =====================
# Scenarios — priority filter
# =====================


def test_priority_filter_excludes_below_threshold(
    caplog: Any,
) -> None:
    """Verify that alerts below the priority threshold are excluded."""
    # _given_ a batch with priority "MEDIUM" and a threshold of HIGH
    batches = [_build_batch("2024-03-01T10:00:00Z")]
    config = _make_mock_config()
    config.google_secops_siem_incidents.priority_filter = Priority.HIGH
    connector = _given_connector_with_stubs(batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ no bundle should be sent (medium < high threshold)
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert not any(
        "Bundle sent" in m for m in all_messages
    ), "Expected no bundle to be sent when priority is below threshold"


def test_priority_filter_includes_at_threshold(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that alerts at the priority threshold are imported."""
    # _given_ a threshold of MEDIUM (matching the test batch priority)
    config = _make_mock_config()
    config.google_secops_siem_incidents.priority_filter = Priority.MEDIUM
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent normally
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when priority meets threshold"


def test_priority_filter_includes_above_threshold(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that alerts above the priority threshold are imported."""
    # _given_ a threshold of LOW (medium > low)
    config = _make_mock_config()
    config.google_secops_siem_incidents.priority_filter = Priority.LOW
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when priority is above threshold"


def test_priority_filter_none_imports_all(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that None priority filter imports all alerts regardless of priority."""
    # _given_ no priority filter (default behavior)
    config = _make_mock_config()
    config.google_secops_siem_incidents.priority_filter = None
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent (all alerts imported)
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when priority filter is None (all pass)"


# =====================
# Stub builders — risk score
# =====================


def _build_batch_with_risk(
    detection_ts: str, risk_score: str = "75"
) -> RuleAlertResponse:
    """Build a RuleAlertResponse with risk_score outcomes on each alert."""
    alert1 = AlertFactory.build(
        fields=[AlertFieldFactory.build(name="ip", string_val="10.0.0.1")],
        outcomes=make_multi_hostname_outcomes(["host1a.local", "host1b.local"])
        + make_ip_outcomes(["10.0.0.1", "10.0.0.2"])
        + [make_risk_score_outcome(risk_score)],
        detection_timestamp=detection_ts,
    )
    alert2 = AlertFactory.build(
        fields=[AlertFieldFactory.build(name="ip", string_val="10.0.0.3")],
        outcomes=make_hostname_outcomes("host2.local")
        + make_ip_outcomes(["10.0.0.3"])
        + [make_risk_score_outcome(risk_score)],
        detection_timestamp=detection_ts,
    )
    rule_alert = RuleAlertFactory.build(
        alerts=[alert1, alert2],
        rule_metadata=RuleMetadataFactory.build(
            properties=RulePropertiesFactory.build(
                metadata={
                    "severity": "MEDIUM",
                    "priority": "MEDIUM",
                    "tags": "test",
                },
            ),
        ),
    )
    return RuleAlertResponseFactory.build(rule_alerts=[rule_alert])


# =====================
# Scenarios — risk score filter
# =====================


def test_risk_score_filter_excludes_below_threshold(
    caplog: Any,
) -> None:
    """Verify that alerts with risk score below the threshold are excluded."""
    # _given_ a batch with risk_score=75 and a threshold of 80
    batches = [_build_batch_with_risk("2024-03-01T10:00:00Z", risk_score="75")]
    config = _make_mock_config()
    config.google_secops_siem_incidents.risk_score_filter = 80
    connector = _given_connector_with_stubs(batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ no bundle should be sent (75 < 80)
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert not any(
        "Bundle sent" in m for m in all_messages
    ), "Expected no bundle to be sent when risk score is below threshold"


def test_risk_score_filter_includes_at_threshold(
    caplog: Any,
) -> None:
    """Verify that alerts with risk score equal to the threshold are imported."""
    # _given_ a batch with risk_score=75 and a threshold of 75
    batches = [_build_batch_with_risk("2024-03-01T10:00:00Z", risk_score="75")]
    config = _make_mock_config()
    config.google_secops_siem_incidents.risk_score_filter = 75
    connector = _given_connector_with_stubs(batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when risk score meets threshold"


def test_risk_score_filter_includes_above_threshold(
    caplog: Any,
) -> None:
    """Verify that alerts with risk score above the threshold are imported."""
    # _given_ a batch with risk_score=90 and a threshold of 50
    batches = [_build_batch_with_risk("2024-03-01T10:00:00Z", risk_score="90")]
    config = _make_mock_config()
    config.google_secops_siem_incidents.risk_score_filter = 50
    connector = _given_connector_with_stubs(batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when risk score is above threshold"


def test_risk_score_filter_none_imports_all(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that None risk score filter imports all alerts."""
    # _given_ no risk score filter (default behavior)
    config = _make_mock_config()
    config.google_secops_siem_incidents.risk_score_filter = None
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent (all alerts imported)
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when risk score filter is None (all pass)"


def test_risk_score_filter_passes_alerts_without_risk_score(
    caplog: Any,
) -> None:
    """Verify that alerts without a risk_score outcome pass through the filter."""
    # _given_ a batch without risk_score outcomes and a threshold of 50
    batches = [_build_batch("2024-03-01T10:00:00Z")]
    config = _make_mock_config()
    config.google_secops_siem_incidents.risk_score_filter = 50
    connector = _given_connector_with_stubs(batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent (no risk score = pass)
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when alerts have no risk score"


# =====================
# Scenarios — tags filter
# =====================


def test_tags_include_accepts_matching_tag(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that alerts with a matching include tag are imported."""
    # _given_ batches with tag "test" and include filter ["test"]
    config = _make_mock_config()
    config.google_secops_siem_incidents.tags_include = ["test"]
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when alert tag matches include filter"


def test_tags_include_rejects_non_matching_tag(
    caplog: Any,
) -> None:
    """Verify that alerts without a matching include tag are filtered out."""
    # _given_ batches with tag "test" and include filter ["phishing"]
    batches = [_build_batch("2024-03-01T10:00:00Z")]
    config = _make_mock_config()
    config.google_secops_siem_incidents.tags_include = ["phishing"]
    connector = _given_connector_with_stubs(batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ no bundle sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert not any(
        "Bundle sent" in m for m in all_messages
    ), "Expected no bundle when alert tags don't match include filter"


def test_tags_exclude_rejects_matching_tag(
    caplog: Any,
) -> None:
    """Verify that alerts with an excluded tag are filtered out."""
    # _given_ batches with tag "test" and exclude filter ["test"]
    batches = [_build_batch("2024-03-01T10:00:00Z")]
    config = _make_mock_config()
    config.google_secops_siem_incidents.tags_exclude = ["test"]
    connector = _given_connector_with_stubs(batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ no bundle sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert not any(
        "Bundle sent" in m for m in all_messages
    ), "Expected no bundle when alert tag matches exclude filter"


def test_tags_exclude_accepts_non_matching_tag(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that alerts without excluded tags are imported."""
    # _given_ batches with tag "test" and exclude filter ["malware"]
    config = _make_mock_config()
    config.google_secops_siem_incidents.tags_exclude = ["malware"]
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when alert tags don't match exclude filter"


def test_tags_filter_none_imports_all(
    two_batches: list[RuleAlertResponse],
    caplog: Any,
) -> None:
    """Verify that no tag filter imports all alerts."""
    # _given_ no tag filters (default)
    config = _make_mock_config()
    config.google_secops_siem_incidents.tags_include = None
    config.google_secops_siem_incidents.tags_exclude = None
    connector = _given_connector_with_stubs(two_batches, config=config)

    # _when_ process_message() is called
    _when_process_message_runs(connector, caplog)

    # _then_ bundles are sent
    all_messages = [rec.getMessage() for rec in caplog.records]
    assert any(
        "Bundle sent" in m for m in all_messages
    ), "Expected bundles to be sent when no tag filters are set"
