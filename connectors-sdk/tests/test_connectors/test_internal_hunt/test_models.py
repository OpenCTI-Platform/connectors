# pragma: no cover
# type: ignore
"""Tests of the internal hunt protocol models."""

from datetime import datetime, timezone

import pytest
from connectors_sdk.connectors.internal_hunt import (
    HuntEvent,
    HuntLimits,
    HuntRequest,
    HuntResult,
    HuntRunMode,
    HuntRunReport,
    HuntRunStatus,
    HuntTimeWindow,
    NativeQuery,
)
from pydantic import ValidationError


def test_hunt_request_parses_the_dispatch_message(hunt_event):
    # Given a hunt run message as sent by OpenCTI
    event = hunt_event()

    # When it is parsed
    request = HuntRequest.model_validate(event)

    # Then every part of the contract is available
    assert request.mode is HuntRunMode.EXECUTE
    assert request.hunt_run.id == "run-1"
    assert request.hunt.techniques[0].x_mitre_id == "T1059.001"
    assert request.hunt.targets[0].entity_type == "Intrusion-Set"
    assert request.hunt.indicators[0].pattern_type == "stix"
    assert request.limits.evidence_max_value_length == 16
    assert request.security_platform.name == "Test SIEM"
    assert request.time_window.start == datetime(2026, 10, 3, tzinfo=timezone.utc)


def test_hunt_request_tolerates_nulls_and_unknown_fields(hunt_event):
    # Given a message with null lists, null limits and fields unknown to this SDK
    event = hunt_event(
        hunt={
            "expected_observables": None,
            "benign_patterns": None,
            "object_marking_refs": None,
            "techniques": None,
            "targets": None,
            "indicators": None,
            "future_field": "ignored",
        },
        limits=None,
        security_platform=None,
        new_top_level_field=True,
    )

    # When it is parsed
    request = HuntRequest.model_validate(event)

    # Then nulls become empty lists or defaults
    assert request.hunt.expected_observables == []
    assert request.hunt.techniques == []
    assert request.limits == HuntLimits()
    assert request.security_platform is None


def test_hunt_time_window_rejects_inverted_bounds():
    # Given/When/Then a window ending before it starts is rejected
    with pytest.raises(ValidationError):
        HuntTimeWindow(start="2026-10-04T00:00:00Z", end="2026-10-03T00:00:00Z")


def test_hunt_request_rejects_other_event_types(hunt_event):
    # Given/When/Then a message of another connector type is rejected
    with pytest.raises(ValidationError):
        HuntRequest.model_validate(hunt_event(event_type="INTERNAL_ENRICHMENT"))


def test_hunt_result_hits_count():
    # Given results with and without a platform total
    events = [HuntEvent(fields={"a": 1}), HuntEvent(fields={"a": 2})]

    # When/Then the hit count is the platform total, never lower than the events
    assert HuntResult(events=events).hits_count == 2
    assert HuntResult(events=events, total_hits=10).hits_count == 10
    assert HuntResult(events=events, total_hits=1).hits_count == 2


def test_native_query_and_report_models():
    # Given/When the result models are built
    query = NativeQuery(language="spl", query="index=main")
    report = HuntRunReport(status=HuntRunStatus.FAILED, error="boom")

    # Then defaults are applied
    assert query.translated is False
    assert query.fields == ()
    assert report.status == "failed"
    with pytest.raises(ValidationError):
        NativeQuery(language="spl", query="")
