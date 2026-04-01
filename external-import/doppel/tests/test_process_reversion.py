import logging
from typing import Any
from uuid import uuid4

import pytest


@pytest.fixture
def fake_indicators(monkeypatch, converter):
    indicators = [{"id": "fakeid", "standard_id": f"note--{uuid4()}", "revoked": False}]
    monkeypatch.setattr(
        converter, "_find_indicators_by_alert_id", lambda *_: indicators
    )


@pytest.fixture
def expected_report_log_messages() -> list[str]:
    """Fixture for expected log messages in report orchestration."""
    return [
        "[DoppelConverter] Processing reversion workflow - {'alert_id': 'test id', 'queue_state': 'unresolved'}",
        "[DoppelConverter] Revoking indicator - {'alert_id': 'test id', 'indicator_id': 'fakeid'}",
        "[DoppelConverter] Successfully revoked indicator via API - {'alert_id': 'test id', 'indicator_id': 'fakeid'}",
        "[DoppelConverter] Revoked indicators - {'alert_id': 'test id', 'revoked_indicators_count': 1}",
    ]


# --------------------------
# --- Scenario Functions ---
# --------------------------


# Scenario: If the alert moves from Actioned/Taken Down back to unresolved
def test_alert_taken_down_to_unresolved(
    converter, fake_indicators, caplog, expected_report_log_messages
):
    # Given alert
    alert = _given_an_alert(caplog)
    # When we call _process_reversion function
    _when_call_process_reversion(converter, alert)
    # Then the observable has been reverted from taken_down state to unresolved
    _then_observable_is_unresolved(converter, fake_indicators)
    # Then the process of reversion should complete successfully with expected logs
    _then_process_reversion_completed_successfully(caplog, expected_report_log_messages)


# ---------------------------------------------------------
# --- Helper Functions (implementing the Gherkin steps) ---
# ---------------------------------------------------------


# Given an alert
def _given_an_alert(caplog):
    caplog.set_level(logging.DEBUG)
    return {
        "id": "test id",
        "queue_state": "unresolved",
        "last_activity_timestamp": "2026-02-26T15:08:24.537482",
    }


# When we call _process_reversion function
def _when_call_process_reversion(converter, alert):
    return converter._process_reversion(
        alert=alert,
        observable_id=f"domain--{uuid4()}",
        stix_objects=[],
        observable_name="obs name",
    )


# Then the observable has been reverted from taken_down state to unresolved
def _then_observable_is_unresolved(converter, indicator):
    converter.helper.api.indicator.update_field.assert_called_once_with(
        id="fakeid", input={"key": "revoked", "value": True}
    )
    converter.helper.api.label.create.assert_called_once_with(
        value="revoked-false-positive"
    )
    converter.helper.api.indicator.add_label.assert_called_once_with(
        id="fakeid", label_id="label_id"
    )


# Then the process of reversion should complete successfully with expected logs
def _then_process_reversion_completed_successfully(
    caplog: Any, expected_report_log_messages: list[str]
) -> None:
    """Verify that process reversion completed successfully with expected logs."""
    all_messages = [rec.getMessage() for rec in caplog.records]
    missing_messages = [
        msg
        for msg in expected_report_log_messages
        if not any(msg in log_msg for log_msg in all_messages)
    ]

    assert (  # noqa: S101
        not missing_messages
    ), f"Missing expected log messages: {missing_messages}"
