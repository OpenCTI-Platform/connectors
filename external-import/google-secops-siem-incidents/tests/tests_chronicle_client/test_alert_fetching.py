"""RED tests — Chronicle rule alert fetching with backward-sliding pagination.

Tests that GoogleSecOpsApiClient.fetch_rule_alerts handles single-batch,
multi-batch pagination, safety guards, empty responses, and error propagation.
"""

from unittest.mock import AsyncMock, patch

import pytest
from google_secops_siem_incidents.models.rule_alert_response import RuleAlertResponse
from google_secops_siem_incidents.utils.api_engine.exceptions import (
    ApiCircuitOpenError,
    ApiHttpError,
    ApiNetworkError,
    ApiRateLimitError,
    ApiTimeoutError,
)

from tests.tests_chronicle_client.factories import (
    AlertFactory,
    RuleAlertFactory,
    RuleAlertResponseFactory,
    make_client,
    make_config,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
async def _collect_batches(client, start, end, **kwargs) -> list[RuleAlertResponse]:
    """Drain fetch_rule_alerts async generator into a list."""
    batches: list[RuleAlertResponse] = []
    async for batch in client.fetch_rule_alerts(start, end, **kwargs):
        batches.append(batch)
    return batches


# ---------------------------------------------------------------------------
# Scenario: All alerts fit in a single batch
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_single_batch_when_all_alerts_fit():
    """tooManyAlerts=false → exactly one batch yielded."""

    def _given_single_batch_response():
        return RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    alerts=[
                        AlertFactory.build(detection_timestamp="2025-01-01T02:00:00Z"),
                        AlertFactory.build(detection_timestamp="2025-01-01T04:00:00Z"),
                        AlertFactory.build(detection_timestamp="2025-01-01T06:00:00Z"),
                    ]
                )
            ],
            too_many_alerts=False,
        )

    config = make_config()
    client, _ = make_client(config)
    batch = _given_single_batch_response()

    with patch.object(client, "_api_client", create=True) as mock_api:
        mock_api.call_api = AsyncMock(return_value=batch)
        batches = await _collect_batches(
            client, "2025-01-01T00:00:00Z", "2025-01-01T12:00:00Z"
        )

    assert len(batches) == 1
    assert sum(len(ra.alerts) for ra in batches[0].rule_alerts) == 3


# ---------------------------------------------------------------------------
# Scenario: Pagination slides backward when too many alerts are returned
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_pagination_slides_backward_on_too_many_alerts():
    """tooManyAlerts=true on first call → second call with updated endTime."""

    def _given_two_batch_responses():
        first = RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    alerts=[
                        AlertFactory.build(detection_timestamp="2025-01-01T06:00:00Z")
                    ]
                )
            ],
            too_many_alerts=True,
        )
        second = RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    alerts=[
                        AlertFactory.build(detection_timestamp="2025-01-01T02:00:00Z")
                    ]
                )
            ],
            too_many_alerts=False,
        )
        return [first, second]

    config = make_config()
    client, _ = make_client(config)
    responses = _given_two_batch_responses()

    with patch.object(client, "_api_client", create=True) as mock_api:
        mock_api.call_api = AsyncMock(side_effect=responses)
        batches = await _collect_batches(
            client, "2025-01-01T00:00:00Z", "2025-01-01T12:00:00Z"
        )

    assert len(batches) == 2


# ---------------------------------------------------------------------------
# Scenario: The start time is never mutated during backward pagination
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_start_time_is_never_mutated():
    """Every API call must use the original startTime; only endTime slides back."""

    def _given_two_batch_responses():
        first = RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    alerts=[
                        AlertFactory.build(detection_timestamp="2025-01-01T06:00:00Z")
                    ]
                )
            ],
            too_many_alerts=True,
        )
        second = RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    alerts=[
                        AlertFactory.build(detection_timestamp="2025-01-01T02:00:00Z")
                    ]
                )
            ],
            too_many_alerts=False,
        )
        return [first, second]

    config = make_config()
    client, _ = make_client(config)
    responses = _given_two_batch_responses()

    with patch.object(client, "_api_client", create=True) as mock_api:
        mock_api.call_api = AsyncMock(side_effect=responses)
        await _collect_batches(client, "2025-01-01T00:00:00Z", "2025-01-01T12:00:00Z")

        for c in mock_api.call_api.call_args_list:
            _, kwargs = c
            assert kwargs["params"]["timeRange.startTime"] == "2025-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Scenario: Pagination stops when no backward progress is possible
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_pagination_stops_when_no_backward_progress():
    """min(detectionTimestamp)==startTime → safety guard stops after 1 batch."""

    def _given_stuck_response():
        return RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    alerts=[
                        AlertFactory.build(detection_timestamp="2025-01-01T00:00:00Z")
                    ]
                )
            ],
            too_many_alerts=True,
        )

    config = make_config()
    client, _ = make_client(config)
    stuck = _given_stuck_response()

    with patch.object(client, "_api_client", create=True) as mock_api:
        mock_api.call_api = AsyncMock(return_value=stuck)
        batches = await _collect_batches(
            client, "2025-01-01T00:00:00Z", "2025-01-01T12:00:00Z"
        )

    assert len(batches) == 1


# ---------------------------------------------------------------------------
# Scenario: endTime of the second request is T_min (exclusive-end boundary)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_second_request_endtime_is_tmin():
    """Backward pagination: second endTime = T_min (raw, no offset).

    Since the API interval is [startTime, endTime) — exclusive end — using
    T_min directly excludes it from the next window without any arithmetic.
    """

    def _given_two_batch_responses():
        first = RuleAlertResponseFactory.build(
            rule_alerts=[
                RuleAlertFactory.build(
                    alerts=[
                        AlertFactory.build(detection_timestamp="2025-01-01T06:00:00Z")
                    ]
                )
            ],
            too_many_alerts=True,
        )
        second = RuleAlertResponseFactory.build(rule_alerts=[], too_many_alerts=False)
        return [first, second]

    config = make_config()
    client, _ = make_client(config)
    responses = _given_two_batch_responses()

    with patch.object(client, "_api_client", create=True) as mock_api:
        mock_api.call_api = AsyncMock(side_effect=responses)
        await _collect_batches(client, "2025-01-01T00:00:00Z", "2025-01-01T12:00:00Z")

        second_call_kwargs = mock_api.call_api.call_args_list[1][1]
        assert (
            second_call_kwargs["params"]["timeRange.endTime"] == "2025-01-01T06:00:00Z"
        )


# ---------------------------------------------------------------------------
# Scenario: tooManyAlerts true but zero alerts stops safely
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_too_many_alerts_but_zero_alerts_stops():
    """tooManyAlerts=true + 0 rule_alerts → single batch, no further calls."""

    def _given_empty_too_many_response():
        return RuleAlertResponseFactory.build(rule_alerts=[], too_many_alerts=True)

    config = make_config()
    client, _ = make_client(config)
    empty = _given_empty_too_many_response()

    with patch.object(client, "_api_client", create=True) as mock_api:
        mock_api.call_api = AsyncMock(return_value=empty)
        batches = await _collect_batches(
            client, "2025-01-01T00:00:00Z", "2025-01-01T12:00:00Z"
        )

    assert len(batches) == 1
    assert len(batches[0].rule_alerts) == 0


# ---------------------------------------------------------------------------
# Scenario: Empty response produces a single empty batch
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_empty_response_produces_single_empty_batch():
    """No rule alerts + tooManyAlerts=false → 1 empty batch."""

    def _given_empty_response():
        return RuleAlertResponseFactory.build(rule_alerts=[], too_many_alerts=False)

    config = make_config()
    client, _ = make_client(config)
    empty = _given_empty_response()

    with patch.object(client, "_api_client", create=True) as mock_api:
        mock_api.call_api = AsyncMock(return_value=empty)
        batches = await _collect_batches(
            client, "2025-01-01T00:00:00Z", "2025-01-01T12:00:00Z"
        )

    assert len(batches) == 1
    assert len(batches[0].rule_alerts) == 0


# ---------------------------------------------------------------------------
# Scenario Outline: Upstream errors propagate unmodified
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc_class,exc_args",
    [
        (ApiHttpError, ("upstream error", 500)),
        (ApiNetworkError, ("connection refused",)),
        (ApiTimeoutError, ("request timed out",)),
        (ApiCircuitOpenError, ("circuit open",)),
        (ApiRateLimitError, ("rate limited",)),
    ],
)
async def test_upstream_errors_propagate(exc_class, exc_args):
    """A <exc_class> raised by the engine propagates through fetch_rule_alerts."""

    config = make_config()
    client, _ = make_client(config)
    exc = exc_class(*exc_args)

    with patch.object(client, "_api_client", create=True) as mock_api:
        mock_api.call_api = AsyncMock(side_effect=exc)
        with pytest.raises(type(exc)):
            async for _ in client.fetch_rule_alerts(
                "2025-01-01T00:00:00Z", "2025-01-01T12:00:00Z"
            ):
                pass
