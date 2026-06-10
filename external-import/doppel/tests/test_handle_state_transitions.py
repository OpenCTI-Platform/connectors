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
def fake_no_indicators(monkeypatch, converter):
    """Mock that no existing indicators are found."""
    monkeypatch.setattr(
        converter, "_find_indicators_by_alert_id_or_entity_value", lambda *_: []
    )


@pytest.fixture
def expected_log_messages_with_alert_taken_down() -> list[str]:
    """Fixture for expected log messages in takedown workflow."""
    return [
        "[DoppelConverter - Handle Indicator] Processing a new indicator",
        "[create indicator] Indicator created",
    ]


@pytest.fixture
def expected_log_messages_with_alert_reverted() -> list[str]:
    """Fixture for expected log messages in reversion workflow."""
    return [
        "[DoppelConverter - Handle Indicator] Processing a new indicator",
        "[DoppelConverter] Alert is not in takedown state, skipping indicator creation",
    ]


@pytest.fixture
def expected_log_messages_with_alert_reverted_without_previous_state() -> list[str]:
    """Fixture for expected log messages in reversion without previous state."""
    return [
        "[DoppelConverter - Handle Indicator] Processing a new indicator",
        "[DoppelConverter] Alert is not in takedown state, skipping indicator creation",
    ]


# --------------------------
# --- Scenario Functions ---
# --------------------------


# Scenario: Handle state transitions if observable does not exists
def test_handle_state_transition_with_new_alert(
    converter,
    fake_no_indicators,
    caplog,
):
    # Given alert
    alert = _given_an_alert(caplog, queue_state="taken_down")
    # And a DomainName observable
    obs = _make_domain()
    # When alert does not already exists in octi
    converter.helper.api.stix_cyber_observable.read.return_value = None
    # And we call the converter to handle the alert
    _when_call_handle_state_transitions(obs, converter, alert)
    # Then the process should complete successfully
    _then_process_takedown_completed_successfully(caplog, [])


# Scenario: Handle state transitions with queue_state to "taken down"
# if observable already exists with queue state to reverted
def test_handle_state_transition_with_alert_taken_down(
    converter, fake_no_indicators, caplog, expected_log_messages_with_alert_taken_down
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
    # And we call the converter to handle the alert
    _when_call_handle_state_transitions(obs, converter, alert)
    # Then the process should complete successfully with expected logs
    _then_process_takedown_completed_successfully(
        caplog, expected_log_messages_with_alert_taken_down
    )


# Scenario: Handle state transitions with queue_state in reverted state
# if observable already exists with queue state to taken down
def test_handle_state_transition_with_alert_reverted_with_previous_state_reverted(
    converter, fake_no_indicators, caplog, expected_log_messages_with_alert_reverted
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
    # And we call the converter to handle the alert
    _when_call_handle_state_transitions(obs, converter, alert)
    # Then the process should complete successfully with expected logs
    _then_process_takedown_completed_successfully(
        caplog, expected_log_messages_with_alert_reverted
    )


# Scenario: Handle state transitions with queue_state in reverted state
# if observable already exists without a previous queue state
def test_handle_state_transition_with_alert_reverted_without_previous_state(
    converter, fake_no_indicators, caplog, expected_log_messages_with_alert_reverted_without_previous_state
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
    # And we call the converter to handle the alert
    _when_call_handle_state_transitions(obs, converter, alert)
    # Then the process should complete successfully with expected logs
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


# When we call the converter to handle alerts
def _when_call_handle_state_transitions(obs, converter, alert):
    # Test the actual convert_alerts_to_stix workflow
    stix_objects = []
    observables = [obs]
    return converter._handle_indicators(alert, observables, stix_objects)


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
