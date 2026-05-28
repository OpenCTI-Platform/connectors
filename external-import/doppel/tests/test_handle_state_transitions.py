import logging
from typing import Any

import pytest
from stix2 import DomainName


def _make_domain() -> DomainName:
    """Mock domain name."""
    return DomainName(
        id="domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058",
        value="Test domain",
    )


@pytest.fixture
def expected_log_messages_with_alert_taken_down() -> list[str]:
    """Fixture for expected log messages in report orchestration."""
    return [
        "[Handle state transition] Observable found in OCTI - {'current_observable_id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'observable_octi': {'id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'objectLabel': [{'value': 'queue_state:doppel_review'}]}}",
        "[Handle state transition] Transition to process takedown - {'current_observable_id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'is_takedown_now': True, 'previous_queue_state': 'doppel_review'}",
        "[DoppelConverter] Processing takedown workflow - {'alert_id': 'test id', 'queue_state': 'taken_down'}",
        "[DoppelConverter] Found indicators for alert_id - {'alert_id': 'test id', 'count': 0}",
    ]


@pytest.fixture
def expected_log_messages_with_alert_reverted() -> list[str]:
    """Fixture for expected log messages in report orchestration."""
    return [
        "[Handle state transition] Observable found in OCTI - {'current_observable_id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'observable_octi': {'id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'objectLabel': [{'value': 'queue_state:taken_down'}]}}",
        "[Handle state transition] Transition to process reversion - {'current_observable_id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'is_takedown_now': False, 'previous_queue_state': 'taken_down'}",
        "[DoppelConverter] Processing reversion workflow - {'alert_id': 'test id', 'queue_state': 'doppel_review'}",
        "[DoppelConverter] Found indicators for alert_id - {'alert_id': 'test id', 'count': 0}",
        "[DoppelConverter] No indicators found to revoke - {'alert_id': 'test id'}",
    ]


@pytest.fixture
def expected_log_messages_with_alert_reverted_without_previous_state() -> list[str]:
    """Fixture for expected log messages in report orchestration."""
    return [
        "[Handle state transition] Observable found in OCTI - {'current_observable_id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'observable_octi': {'id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'objectLabel': []}}",
        "[Handle state transition] Transition to process reversion - {'current_observable_id': 'domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058', 'previous_queue_state': None}",
        "[DoppelConverter] Processing reversion workflow - {'alert_id': 'test id', 'queue_state': 'doppel_review'}",
        "[DoppelConverter] Found indicators for alert_id - {'alert_id': 'test id', 'count': 0}",
        "[DoppelConverter] No indicators found to revoke - {'alert_id': 'test id'}",
    ]


# --------------------------
# --- Scenario Functions ---
# --------------------------


# Scenario: Handle state transitions if observable does not exists
def test_handle_state_transition_with_new_alert(
    converter,
    caplog,
):
    # Given alert
    alert = _given_an_alert(caplog, queue_state="taken down")
    # And a DomainName observable
    obs = _make_domain()
    # When alert does not already exists in octi
    converter.helper.api.stix_cyber_observable.read.return_value = None
    # And we call _handle_state_transitions function
    _when_call_handle_state_transitions(obs, converter, alert)
    # Then the process takedown should complete successfully with expected logs
    _then_process_takedown_completed_successfully(caplog, [])


# Scenario: Handle state transitions with queue_state to "taken down"
# if observable already exists with queue state to reverted
def test_handle_state_transition_with_alert_taken_down(
    converter, caplog, expected_log_messages_with_alert_taken_down
):
    # Given an alert with queue_state taken down
    alert = _given_an_alert(caplog, queue_state="taken_down")
    # And a DomainName observable
    obs = _make_domain()
    # When alert already exists in octi as observable
    converter.helper.api.stix_cyber_observable.read.return_value = {
        "id": "domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058",
        "objectLabel": [{"value": "queue_state:doppel_review"}],
    }
    # And we call _handle_state_transitions function
    _when_call_handle_state_transitions(obs, converter, alert)
    # Then the process takedown should complete successfully with expected logs
    _then_process_takedown_completed_successfully(
        caplog, expected_log_messages_with_alert_taken_down
    )


# Scenario: Handle state transitions with queue_state in reverted state
# if observable already exists with queue state to taken down
def test_handle_state_transition_with_alert_reverted_with_previous_state_reverted(
    converter, caplog, expected_log_messages_with_alert_reverted
):
    # Given an alert with queue_state in reverted state
    alert = _given_an_alert(caplog, queue_state="doppel_review")
    # And a DomainName observable
    obs = _make_domain()
    # When alert already exists in octi as observable with "taken down" label
    converter.helper.api.stix_cyber_observable.read.return_value = {
        "id": "domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058",
        "objectLabel": [{"value": "queue_state:taken_down"}],
    }
    # And we call _handle_state_transitions function
    _when_call_handle_state_transitions(obs, converter, alert)
    # Then the process takedown should complete successfully with expected logs
    _then_process_takedown_completed_successfully(
        caplog, expected_log_messages_with_alert_reverted
    )


# Scenario: Handle state transitions with queue_state in reverted state
# if observable already exists without a previous queue state
def test_handle_state_transition_with_alert_reverted_without_previous_state(
    converter, caplog, expected_log_messages_with_alert_reverted_without_previous_state
):
    # Given an alert with queue_state in reverted state
    alert = _given_an_alert(caplog, queue_state="doppel_review")
    # And a DomainName observable
    obs = _make_domain()
    # When alert already exists in octi as observable without queue_state label
    converter.helper.api.stix_cyber_observable.read.return_value = {
        "id": "domain-name--e5651b2a-2840-4e94-9e6d-e4da28565058",
        "objectLabel": [],
    }
    # And we call _handle_state_transitions function
    _when_call_handle_state_transitions(obs, converter, alert)
    # Then the process takedown should complete successfully with expected logs
    _then_process_takedown_completed_successfully(
        caplog, expected_log_messages_with_alert_reverted_without_previous_state
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


# When we call _handle_state_transitions function
def _when_call_handle_state_transitions(obs, converter, alert):
    return converter._handle_state_transitions(
        alert_queue_state=alert["queue_state"],
        current_observable=obs,
        alert=alert,
        stix_objects=[],
        observable_name="obs name",
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
