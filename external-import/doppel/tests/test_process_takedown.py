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
        converter, "_find_indicators_by_alert_id", lambda *_: indicators
    )


@pytest.fixture
def fake_empty_indicators(monkeypatch, converter):
    indicators = None
    monkeypatch.setattr(
        converter, "_find_indicators_by_alert_id", lambda *_: indicators
    )


@pytest.fixture
def expected_log_messages_without_indicator_creation() -> list[str]:
    """Fixture for expected log messages in report orchestration."""
    return [
        "[DoppelConverter] Processing takedown workflow - {'alert_id': 'test id', 'queue_state': 'taken down'}",
        "[DoppelConverter] Un-revoking indicator after re-takedown - {'alert_id': 'test id', 'indicator_standard_id': 'indicator--867322cc-57e2-4027-8dee-3802c6c33ecd'}",
    ]


@pytest.fixture
def expected_log_messages_with_indicator_creation() -> list[str]:
    """Fixture for expected log messages in report orchestration."""
    return [
        "[DoppelConverter] Processing takedown workflow - {'alert_id': 'test id', 'queue_state': 'taken down'}",
        "[Process taken down] New Indicator created - {'alert_id': 'test id', 'name': 'test.com', 'indicator_pattern': \"[domain-name:value = 'test.com']\"}",
        # "[DoppelConverter] Created based-on relationship for new indicator - {'alert_id': 'test id', 'indicator_id': 'indicator--6ca61515-7ea1-538b-8e4d-666bcfba472a', 'observable_id': 'domain--40020b21-186e-4239-8f78-8b67582322c7'}",
        "[DoppelConverter] Created indicator for takedown alert - {'alert_id': 'test id', 'pattern': \"[domain-name:value = 'test.com']\"}",
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


# When we call _process_takedown function
def _when_call_process_takedown(converter, alert):
    return converter._process_takedown(
        alert=alert,
        observable_id=f"domain-name--{uuid4()}",
        stix_objects=[],
        observable_name="obs name",
    )


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
