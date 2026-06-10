import logging
from typing import Any
from uuid import uuid4

import pytest


@pytest.fixture
def fake_indicators_with_results(monkeypatch, converter):
    indicators = [
        {
            "id": "indicator--867322cc-57e2-4027-8dee-3802c6c33ecd",
            "standard_id": "indicator--867322cc-57e2-4027-8dee-3802c6c33ecd",
            "revoked": True,
        }
    ]
    monkeypatch.setattr(
        converter, "_find_indicators_by_alert_id_or_entity_value", lambda *_: indicators
    )


@pytest.fixture
def fake_empty_indicators(monkeypatch, converter):
    indicators = []
    monkeypatch.setattr(
        converter, "_find_indicators_by_alert_id_or_entity_value", lambda *_: indicators
    )


@pytest.fixture
def expected_log_messages_without_indicator_creation() -> list[str]:
    """Fixture for expected log messages in takedown with existing indicator."""
    return [
        "[DoppelConverter - Handle Indicator] Processing existing indicator",
        "[DoppelConverter] Updating indicator revoke status",
    ]


@pytest.fixture
def expected_log_messages_with_indicator_creation() -> list[str]:
    """Fixture for expected log messages in takedown with new indicator."""
    return [
        "[DoppelConverter - Handle Indicator] Processing a new indicator",
        "[create indicator] Indicator created",
    ]


# --------------------------
# --- Scenario Functions ---
# --------------------------


# Scenario: If the alert is marked "taken down" by Doppel
def test_alert_taken_down_with_existing_indicator(
    converter,
    fake_indicators_with_results,
    caplog,
    expected_log_messages_without_indicator_creation,
):
    # Given alert
    alert = _given_an_alert(caplog, queue_state="taken down")
    # When we call _process_takedown function
    _when_call_process_takedown(converter, alert)
    # Then the indicator is unrevoked
    _then_indicator_is_unrevoked(converter, fake_indicators_with_results)
    # Then the process takedown should complete successfully with expected logs
    _then_process_takedown_completed_successfully(
        caplog, expected_log_messages_without_indicator_creation
    )


# Scenario: If the alert is marked "taken down" by Doppel
def test_alert_taken_down_without_existing_indicator(
    converter,
    fake_empty_indicators,
    caplog,
    expected_log_messages_with_indicator_creation,
):
    # Given alert
    alert = _given_an_alert(caplog, queue_state="taken down")
    # When we call _process_takedown function
    _when_call_process_takedown(converter, alert)
    # Then the process takedown should complete successfully with expected logs
    _then_process_takedown_completed_successfully(
        caplog, expected_log_messages_with_indicator_creation
    )


# ---------------------------------------------------------
# --- Helper Functions (implementing the Gherkin steps) ---
# ---------------------------------------------------------


# Given an alert
def _given_an_alert(caplog, queue_state):
    caplog.set_level(logging.DEBUG)
    return {
        "id": "test id",
        "queue_state": queue_state,
        "last_activity_timestamp": "2026-02-26T15:08:24.537482",
        "entity_content": {
            "root_domain": {
                "domain": "test.com",
            }
        },
    }


# When we call _handle_indicators function with takedown alert
def _when_call_process_takedown(converter, alert):
    stix_objects = []
    observables = [{
        "id": f"domain-name--{uuid4()}",
        "type": "domain-name",
        "value": alert.get("entity", "test.com")
    }]
    return converter._handle_indicators(alert, observables, stix_objects)


# Then the observable has a queue_state to taken_down
def _then_indicator_is_unrevoked(converter, indicator):
    converter.helper.api.indicator.update_field.assert_called_once_with(
        id="indicator--867322cc-57e2-4027-8dee-3802c6c33ecd",
        input={"key": "revoked", "value": False},
    )


# Then the process takedown should complete successfully with expected logs
def _then_process_takedown_completed_successfully(
    caplog: Any, expected_report_log_messages: list[str]
) -> None:
    """Verify that process takedown completed successfully with expected logs."""
    all_messages = [rec.getMessage() for rec in caplog.records]
    missing_messages = [
        msg
        for msg in expected_report_log_messages
        if not any(msg in log_msg for log_msg in all_messages)
    ]

    assert (  # noqa: S101
        not missing_messages
    ), f"Missing expected log messages: {missing_messages}"
