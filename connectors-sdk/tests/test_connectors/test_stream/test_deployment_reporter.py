# pragma: no cover  # do not compute coverage on test files
# type: ignore
"""Tests of the deployment reporter."""

import threading
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.stream.deployment.models import (
    DeploymentBatchResult,
    DeploymentReport,
    DeploymentStatus,
)
from connectors_sdk.connectors.stream.deployment.reporter import (
    MAX_BATCH_SIZE,
    MAX_ERROR_MESSAGE_LENGTH,
    MAX_UNSENT_AGE,
    REPORT_REJECTED,
    REPORT_SENT,
    REPORT_UNSENT,
    DeploymentListingError,
    DeploymentReporter,
    is_rate_limit_error,
    is_rejection_error,
)
from connectors_sdk.connectors.stream.deployment.settings import (
    SecurityPlatformConfig,
)

RATE_LIMITED = ValueError({"name": "RATE_LIMIT", "error_message": "Too many requests"})


class Clock:
    """Controllable monotonic clock."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# --- configuration and feature detection --------------------------------------


def test_from_settings_and_properties(graphql_helper, no_atexit):
    """The reporter is built from settings and exposes its collaborators."""
    settings = SimpleNamespace(security_platform=SecurityPlatformConfig(name="My EDR"))
    reporter = DeploymentReporter.from_settings(graphql_helper, settings)
    assert reporter.helper is graphql_helper
    assert reporter.logger is graphql_helper.connector_logger
    assert reporter.enabled is True
    assert reporter.hits_enabled is False
    assert reporter.options.security_platform_name == "My EDR"


def test_hits_are_disabled_when_reporting_is_disabled(
    graphql_helper, make_reporter, options
):
    """Disabling the write-back disables hits too."""
    reporter = make_reporter(graphql_helper, replace(options, reporting_enabled=False))
    assert reporter.hits_enabled is False
    assert reporter.report_indicator_hits("indicator-id", 1) is False


def test_start_when_disabled_by_configuration(
    graphql_helper, make_reporter, options, router
):
    """A disabled write-back never calls OpenCTI."""
    reporter = make_reporter(graphql_helper, replace(options, reporting_enabled=False))
    assert reporter.start() is False
    assert reporter.is_supported() is False
    assert router.calls == []
    graphql_helper.connector_logger.info.assert_called_once()


def test_start_detects_support_and_resolves_the_platform(
    graphql_helper, make_reporter, router, no_atexit, ids
):
    """Starting resolves everything once and registers the exit flush once."""
    reporter = make_reporter(graphql_helper)

    assert reporter.start() is True
    assert reporter.start() is True

    assert len(router.calls_of("DeploymentWriteBackFeatures")) == 1
    platform_inputs = router.calls_of("DeploymentSecurityPlatformAdd")
    assert platform_inputs == [
        {
            "input": {
                "name": "Test Platform",
                "update": True,
                "security_platform_type": "EDR",
            }
        }
    ]
    assert reporter.security_platform_id == ids.platform
    assert no_atexit == [reporter.close]


def test_detection_and_resolution_calls_never_hold_the_state_lock(
    graphql_helper, make_reporter, router, no_atexit
):
    """The stream thread takes the state lock to queue its outcomes: a slow OpenCTI
    call detecting the write-back or resolving the platform never makes it wait."""
    reporter = make_reporter(graphql_helper)
    lock_free = []

    def probe():
        acquired = reporter._lock.acquire(timeout=5)
        if acquired:
            reporter._lock.release()
        lock_free.append(acquired)

    def query(*args, **kwargs):
        thread = threading.Thread(target=probe)
        thread.start()
        thread.join()
        return router(*args, **kwargs)

    graphql_helper.api.query.side_effect = query

    assert reporter.start() is True
    assert lock_free == [True, True]


def test_detection_and_resolution_running_in_another_thread_are_not_awaited(
    graphql_helper, make_reporter, router, no_atexit, ids
):
    reporter = make_reporter(graphql_helper)
    with reporter._detection_lock, reporter._resolution_lock:
        assert reporter.is_supported() is False
        assert reporter.security_platform_id is None
    assert router.calls_of("DeploymentWriteBackFeatures") == []
    assert router.calls_of("DeploymentSecurityPlatformAdd") == []

    assert reporter.start() is True
    with reporter._detection_lock, reporter._resolution_lock:
        assert reporter.is_supported() is True
        assert reporter.security_platform_id == ids.platform


def test_start_on_a_platform_without_the_write_back(
    graphql_helper, make_reporter, router, router_factory
):
    """Older platforms make the reporter a no-op, logged once at info level."""
    router.handlers.update(router_factory(mutations=("stixCoreObjectEdit",)).handlers)
    reporter = make_reporter(graphql_helper)

    assert reporter.start() is False
    assert reporter.is_supported() is False
    assert reporter.report_indicator_deployment("indicator-id", "deployed") is False

    unsupported_logs = [
        call
        for call in graphql_helper.connector_logger.info.call_args_list
        if "does not support" in call.args[0]
    ]
    assert len(unsupported_logs) == 1
    assert router.calls_of("DeploymentSecurityPlatformAdd") == []
    assert len(router.calls_of("DeploymentWriteBackFeatures")) == 1


def test_start_registers_the_exit_flush_when_opencti_is_unreachable(
    graphql_helper, make_reporter, router, no_atexit
):
    """A failed startup detection still flushes the reports queued later at exit."""
    router.handlers["DeploymentWriteBackFeatures"] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper)

    assert reporter.start() is False
    assert no_atexit == [reporter.close]


def test_feature_detection_failure_is_retried_later(
    graphql_helper, make_reporter, router
):
    """A failed detection is retried after the retry delay, warning only once."""
    clock = Clock()
    original = router.handlers["DeploymentWriteBackFeatures"]
    router.handlers["DeploymentWriteBackFeatures"] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper, monotonic=clock, retry_delay=60.0)

    assert reporter.is_supported() is False
    assert reporter.is_supported() is False  # within the retry delay, no call
    assert len(router.calls_of("DeploymentWriteBackFeatures")) == 1
    clock.now += 61
    assert reporter.is_supported() is False  # retried, still failing
    assert len(router.calls_of("DeploymentWriteBackFeatures")) == 2
    graphql_helper.connector_logger.warning.assert_called_once()
    graphql_helper.connector_logger.debug.assert_called_once()

    router.handlers["DeploymentWriteBackFeatures"] = original
    clock.now += 61
    assert reporter.is_supported() is True


def test_feature_detection_ignores_malformed_fields(
    graphql_helper, make_reporter, router
):
    """Malformed introspection fields are ignored."""
    router.handlers["DeploymentWriteBackFeatures"] = {
        "data": {
            "__type": {
                "fields": [None, {"name": None}, {"name": "indicatorReportDeployment"}]
            }
        }
    }
    reporter = make_reporter(graphql_helper)
    assert reporter.is_supported() is True
    assert reporter.is_supported("indicatorReportHits") is False


def test_feature_detection_with_an_empty_response(
    graphql_helper, make_reporter, router
):
    """An empty introspection response means nothing is supported."""
    router.handlers["DeploymentWriteBackFeatures"] = {"data": None}
    assert make_reporter(graphql_helper).is_supported() is False


# --- security platform ------------------------------------------------------------


def test_configured_security_platform_id_is_used(
    graphql_helper, make_reporter, options, router
):
    """``SECURITY_PLATFORM_ID`` skips the resolution by name."""
    reporter = make_reporter(
        graphql_helper, replace(options, security_platform_id="bound-id")
    )
    assert reporter.security_platform_id == "bound-id"
    assert router.calls_of("DeploymentSecurityPlatformAdd") == []


def test_security_platform_resolution_without_type(
    graphql_helper, make_reporter, options, router
):
    """The type is only sent when configured."""
    reporter = make_reporter(
        graphql_helper, replace(options, security_platform_type=None)
    )
    assert reporter.security_platform_id is not None
    assert router.calls_of("DeploymentSecurityPlatformAdd") == [
        {"input": {"name": "Test Platform", "update": True}}
    ]


@pytest.mark.parametrize(
    "response",
    [
        {"data": {"securityPlatformAdd": None}},
        {"data": {"securityPlatformAdd": {"name": "no id"}}},
        {"data": None},
        ValueError({"name": "FORBIDDEN_ACCESS", "error_message": "Forbidden"}),
    ],
)
def test_security_platform_resolution_failure_is_retried_later(
    graphql_helper, make_reporter, router, response, ids
):
    """A failed resolution is logged and retried after the retry delay."""
    clock = Clock()
    router.handlers["DeploymentSecurityPlatformAdd"] = response
    reporter = make_reporter(graphql_helper, monotonic=clock, retry_delay=60.0)

    assert reporter.security_platform_id is None
    assert reporter.security_platform_id is None
    assert len(router.calls_of("DeploymentSecurityPlatformAdd")) == 1
    graphql_helper.connector_logger.warning.assert_called_once()

    router.handlers["DeploymentSecurityPlatformAdd"] = {
        "data": {"securityPlatformAdd": {"id": ids.platform}}
    }
    clock.now += 61
    assert reporter.security_platform_id == ids.platform
    assert reporter.start() is True


def test_security_platform_resolution_with_the_pycti_helper(
    pycti_helper, make_reporter, ids
):
    """The pycti helper resolves the platform when available."""
    reporter = make_reporter(pycti_helper)
    assert reporter.security_platform_id == ids.platform
    pycti_helper.get_or_create_security_platform.assert_called_once_with(
        "Test Platform", security_platform_type="EDR"
    )


# --- single report ------------------------------------------------------------------


def test_report_indicator_deployment_with_graphql(
    graphql_helper, make_reporter, router, ids
):
    """Single reports send the contract mutation."""
    reporter = make_reporter(graphql_helper)

    assert reporter.report_indicator_deployment(
        ids.indicator,
        "failed",
        external_id="vendor-id",
        error_message="rejected",
        synced_at=datetime(2026, 10, 3, tzinfo=UTC),
    )

    assert router.calls_of("IndicatorReportDeployment(") == [
        {
            "platformId": ids.platform,
            "indicatorId": ids.indicator,
            "status": "failed",
            "externalId": "vendor-id",
            "metadata": {
                "last_sync_at": "2026-10-03T00:00:00.000Z",
                "error_message": "rejected",
            },
        }
    ]


def test_report_indicator_deployment_with_the_pycti_helper(
    pycti_helper, make_reporter, ids
):
    """Single reports use the pycti helper when available."""
    reporter = make_reporter(pycti_helper)

    assert reporter.report_indicator_deployment(
        ids.indicator, DeploymentStatus.DEPLOYED
    )

    pycti_helper.report_indicator_deployment.assert_called_once_with(
        platform_id=ids.platform,
        indicator_id=ids.indicator,
        status="deployed",
        external_id=None,
        error_message=None,
        deployed_at=None,
        synced_at=None,
        removed_at=None,
    )
    pycti_helper.report_indicator_deployment.return_value = None
    assert reporter.report_indicator_deployment(ids.indicator, "deployed") is False


def test_report_indicator_deployment_rejects_invalid_reports(
    graphql_helper, make_reporter, router
):
    """Invalid reports are logged and never sent."""
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_deployment("indicator-id", "expired") is False
    assert reporter.report_indicator_deployment("", "deployed") is False
    assert router.calls == []
    assert graphql_helper.connector_logger.warning.call_count == 2


def test_report_indicator_deployment_errors_never_raise(
    graphql_helper, make_reporter, router
):
    """GraphQL errors are logged as warnings."""
    router.handlers["IndicatorReportDeployment("] = ValueError(
        {"name": "UNSUPPORTED_ERROR", "error_message": "Indicator not found"}
    )
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_deployment("indicator-id", "deployed") is False
    graphql_helper.connector_logger.warning.assert_called_once()


def test_rate_limited_calls_are_retried_with_backoff(
    graphql_helper, make_reporter, router
):
    """``Too many requests`` errors are retried with an exponential backoff."""
    sleeps = []
    responses = iter(
        [
            RATE_LIMITED,
            RATE_LIMITED,
            {"data": {"indicatorReportDeployment": {"id": "relationship"}}},
        ]
    )

    def handler(_variables):
        return next(responses)

    router.handlers["IndicatorReportDeployment("] = handler
    reporter = make_reporter(graphql_helper, sleep=sleeps.append, retry_backoff=0.5)

    assert reporter.report_indicator_deployment("indicator-id", "deployed") is True
    assert sleeps == [0.5, 1.0]


def test_rate_limit_retries_are_bounded(graphql_helper, make_reporter, router):
    """After the last retry, the rate limit error is logged and swallowed."""
    sleeps = []
    router.handlers["IndicatorReportDeployment("] = RATE_LIMITED
    reporter = make_reporter(graphql_helper, sleep=sleeps.append, max_retries=2)

    assert reporter.report_indicator_deployment("indicator-id", "deployed") is False
    assert sleeps == [1.0, 2.0]
    graphql_helper.connector_logger.warning.assert_called_once()


def test_is_rate_limit_error():
    """Rate limit errors are recognized from the GraphQL error text."""
    assert is_rate_limit_error(RATE_LIMITED)
    assert is_rate_limit_error(ValueError("429 Too Many Requests"))
    assert not is_rate_limit_error(ValueError("Forbidden"))


# --- batch reports -------------------------------------------------------------------


def test_report_indicator_deployments_chunks_by_500(
    graphql_helper, make_reporter, router
):
    """Batches are split into chunks of at most 500 reports."""
    reporter = make_reporter(graphql_helper)
    reports = [
        DeploymentReport(indicator_id=f"indicator-{index}", status="active")
        for index in range(2 * MAX_BATCH_SIZE + 1)
    ]

    result = reporter.report_indicator_deployments(reports)

    calls = router.calls_of("IndicatorReportDeployments(")
    assert [len(call["reports"]) for call in calls] == [500, 500, 1]
    assert calls[0]["reports"][0] == {"indicatorId": "indicator-0", "status": "active"}
    assert result.processed == 1001
    assert result.updated == 1001
    assert result.errors == ()


def test_report_indicator_deployments_accepts_helper_mappings(
    graphql_helper, make_reporter, router
):
    """Mappings in the pycti helper shape are accepted; invalid items are skipped."""
    reporter = make_reporter(graphql_helper)

    result = reporter.report_indicator_deployments(
        [
            {
                "indicator_id": "a",
                "status": "removed",
                "removed_at": "2026-10-03T00:00:00Z",
            },
            {"indicator_id": "b", "status": "expired"},
            ("not", "a", "report"),
        ]
    )

    calls = router.calls_of("IndicatorReportDeployments(")
    assert len(calls) == 1
    assert calls[0]["reports"] == [
        {
            "indicatorId": "a",
            "status": "removed",
            "metadata": {"removed_at": "2026-10-03T00:00:00.000Z"},
        }
    ]
    assert result.processed == 1
    assert graphql_helper.connector_logger.warning.call_count == 2


def test_report_indicator_deployments_with_nothing_to_send(
    graphql_helper, make_reporter, router
):
    """No report means no call."""
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_deployments([]) == DeploymentBatchResult()
    assert router.calls == []


def test_report_indicator_deployments_on_an_unsupported_platform(
    graphql_helper, make_reporter, router, router_factory
):
    """Unsupported platforms make batches a no-op."""
    router.handlers.update(router_factory(mutations=()).handlers)
    reporter = make_reporter(graphql_helper)
    result = reporter.report_indicator_deployments(
        [DeploymentReport(indicator_id="a", status="active")]
    )
    assert result == DeploymentBatchResult()


def test_report_indicator_deployments_one_by_one_without_the_batch_mutation(
    graphql_helper, make_reporter, router, router_factory
):
    """Platforms without the batch mutation receive single reports."""
    router.handlers.update(
        router_factory(mutations=("indicatorReportDeployment",)).handlers
    )
    outcomes = iter(
        [
            {"data": {"indicatorReportDeployment": {"id": "relationship"}}},
            ValueError("boom"),
        ]
    )
    router.handlers["IndicatorReportDeployment("] = lambda _variables: next(outcomes)
    reporter = make_reporter(graphql_helper)

    result = reporter.report_indicator_deployments(
        [
            DeploymentReport(indicator_id="a", status="active"),
            DeploymentReport(indicator_id="b", status="active"),
        ]
    )

    assert result.processed == 1
    assert [error.indicator_id for error in result.errors] == ["b"]
    assert router.calls_of("IndicatorReportDeployments(") == []


GRAPHQL_REJECTION = ValueError({"name": "VALIDATION_ERROR", "error_message": "bad"})


def test_rejection_errors_are_told_apart_from_undelivered_calls():
    assert is_rejection_error(GRAPHQL_REJECTION)
    assert not is_rejection_error(
        ValueError({"name": "TOO_MANY_REQUESTS", "error_message": "Too many requests"})
    )
    assert not is_rejection_error(ValueError("<html>502 Bad Gateway</html>"))
    assert not is_rejection_error(ConnectionError("unreachable"))


def test_one_by_one_reports_separate_rejections_from_undelivered_ones(
    graphql_helper, make_reporter, router, router_factory
):
    router.handlers.update(
        router_factory(mutations=("indicatorReportDeployment",)).handlers
    )
    outcomes = iter([GRAPHQL_REJECTION, ConnectionError("unreachable")])
    router.handlers["IndicatorReportDeployment("] = lambda _variables: next(outcomes)
    reporter = make_reporter(graphql_helper)

    result = reporter.report_indicator_deployments(
        [
            DeploymentReport(indicator_id="rejected", status="active"),
            DeploymentReport(indicator_id="undelivered", status="active"),
        ]
    )

    assert sorted(error.indicator_id for error in result.errors) == [
        "rejected",
        "undelivered",
    ]
    assert [report.indicator_id for report in result.unsent] == ["undelivered"]


def test_undelivered_queued_reports_are_sent_again_with_a_growing_delay(
    graphql_helper, make_reporter, router
):
    """An OpenCTI outage never loses a queued stream outcome."""
    router.handlers["IndicatorReportDeployments("] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper, flush_interval=5.0)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="failed"))

    first = reporter.flush()
    assert [report.indicator_id for report in first.unsent] == ["a"]
    assert reporter._unsent_retry_delay == 5.0
    reporter.flush()
    assert reporter._unsent_retry_delay == 10.0

    router.handlers["IndicatorReportDeployments("] = lambda variables: {
        "data": {"indicatorReportDeployments": {"processed": len(variables["reports"])}}
    }
    delivered = reporter.flush()

    assert delivered.processed == 1
    assert reporter._unsent_retry_delay == 0.0
    assert reporter._unsent_since == {}
    assert reporter.flush().processed == 0
    reporter.close()


def test_rejected_queued_reports_are_not_sent_again(
    graphql_helper, make_reporter, router
):
    router.handlers["IndicatorReportDeployments("] = GRAPHQL_REJECTION
    reporter = make_reporter(graphql_helper)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="failed"))

    result = reporter.flush()

    assert [error.indicator_id for error in result.errors] == ["a"]
    assert result.unsent == ()
    assert reporter.flush().errors == ()


def test_newer_queued_report_wins_over_an_undelivered_one(
    graphql_helper, make_reporter, router
):
    reporter = make_reporter(graphql_helper)

    def outage(_variables):
        reporter.enqueue(DeploymentReport(indicator_id="a", status="removed"))
        return ConnectionError("unreachable")

    router.handlers["IndicatorReportDeployments("] = outage
    reporter.enqueue(DeploymentReport(indicator_id="a", status="active"))
    reporter.flush()

    router.handlers["IndicatorReportDeployments("] = lambda variables: {
        "data": {"indicatorReportDeployments": {"processed": len(variables["reports"])}}
    }
    reporter.flush()
    (batch,) = router.calls_of("IndicatorReportDeployments(")[-1:]
    assert [(r["indicatorId"], r["status"]) for r in batch["reports"]] == [
        ("a", "removed")
    ]


def test_undelivered_reports_are_dropped_after_the_maximum_age(
    graphql_helper, make_reporter, router
):
    now = [0.0]
    router.handlers["IndicatorReportDeployments("] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper, monotonic=lambda: now[0])
    reporter.enqueue(DeploymentReport(indicator_id="a", status="failed"))
    reporter.flush()

    now[0] = MAX_UNSENT_AGE + 1
    reporter.flush()

    assert reporter.flush().processed == 0
    assert (
        router.calls_of("IndicatorReportDeployments(")[-1]["reports"][0]["indicatorId"]
        == "a"
    )
    assert reporter._unsent_since == {}
    graphql_helper.connector_logger.warning.assert_any_call(
        "[DEPLOYMENT] Dropping deployment reports undelivered for too long.",
        {"dropped": 1, "max_age_seconds": MAX_UNSENT_AGE},
    )


def test_a_newer_report_replacing_an_undelivered_one_starts_its_own_age(
    graphql_helper, make_reporter, router
):
    """Near the maximum age, the latest outcome of an indicator is not dropped with
    the age of the older report it replaced in the queue."""
    now = [0.0]
    router.handlers["IndicatorReportDeployments("] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper, monotonic=lambda: now[0])
    reporter.enqueue(DeploymentReport(indicator_id="a", status="active"))
    reporter.flush()

    now[0] = MAX_UNSENT_AGE + 1
    newer = DeploymentReport(indicator_id="a", status="removed")
    reporter.enqueue(newer)
    reporter.flush()

    assert reporter._unsent_since["a"] == (newer, MAX_UNSENT_AGE + 1)
    assert reporter._buffer["a"] is newer
    assert all(
        call.args[0]
        != "[DEPLOYMENT] Dropping deployment reports undelivered for too long."
        for call in graphql_helper.connector_logger.warning.call_args_list
    )


def test_pycti_folded_call_failures_are_sent_again(pycti_helper, make_reporter):
    reporter = make_reporter(pycti_helper)
    pycti_helper.report_indicator_deployments.return_value = {
        "processed": 0,
        "errors": [{"indicatorId": "a", "message": "Connection refused"}],
    }
    reporter.enqueue(DeploymentReport(indicator_id="a", status="failed"))
    assert [r.indicator_id for r in reporter.flush().unsent] == ["a"]

    pycti_helper.report_indicator_deployments.return_value = {
        "processed": 0,
        "errors": [
            {
                "indicatorId": "a",
                "message": "{'name': 'FUNCTIONAL_ERROR', 'error_message': 'gone'}",
            }
        ],
    }
    assert reporter.flush().unsent == ()


def test_pycti_folded_rate_limits_are_sent_again(pycti_helper, make_reporter):
    reporter = make_reporter(pycti_helper)
    pycti_helper.report_indicator_deployments.return_value = {
        "processed": 0,
        "errors": [
            {
                "indicatorId": indicator_id,
                "message": "{'name': 'FUNCTIONAL_ERROR', 'error_message': 'Too many requests'}",
            }
            for indicator_id in ("a", "b")
        ],
    }
    reporter.enqueue(DeploymentReport(indicator_id="a", status="deployed"))
    reporter.enqueue(DeploymentReport(indicator_id="b", status="failed"))

    assert sorted(r.indicator_id for r in reporter.flush().unsent) == ["a", "b"]


def test_report_indicator_deployments_logs_rejected_reports(
    graphql_helper, make_reporter, router
):
    """Rejected reports are returned and logged at info level."""
    router.handlers["IndicatorReportDeployments("] = {
        "data": {
            "indicatorReportDeployments": {
                "processed": 1,
                "created": 1,
                "updated": 0,
                "unchanged": 0,
                "errors": [{"indicatorId": "b", "message": "Indicator not found"}],
            }
        }
    }
    reporter = make_reporter(graphql_helper)

    result = reporter.report_indicator_deployments(
        [
            DeploymentReport(indicator_id="a", status="active"),
            DeploymentReport(indicator_id="b", status="removed"),
        ]
    )

    assert result.created == 1
    assert result.errors[0].message == "Indicator not found"
    assert any(
        "not applied" in call.args[0]
        for call in graphql_helper.connector_logger.info.call_args_list
    )


def test_report_indicator_deployments_chunk_errors_never_raise(
    graphql_helper, make_reporter, router
):
    """A failing chunk is reported as errors."""
    router.handlers["IndicatorReportDeployments("] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper)

    result = reporter.report_indicator_deployments(
        [DeploymentReport(indicator_id="a", status="active")]
    )

    assert result.errors[0].indicator_id == "a"
    assert "unreachable" in result.errors[0].message
    graphql_helper.connector_logger.warning.assert_called_once()


def test_report_indicator_deployments_with_the_pycti_helper(
    pycti_helper, make_reporter, ids
):
    """Batches use the pycti helper when available, without empty fields."""
    reporter = make_reporter(pycti_helper)

    result = reporter.report_indicator_deployments(
        [DeploymentReport(indicator_id="a", status="deployed", external_id="v")]
    )

    pycti_helper.report_indicator_deployments.assert_called_once_with(
        ids.platform, [{"indicator_id": "a", "status": "deployed", "external_id": "v"}]
    )
    assert result.created == 1

    pycti_helper.report_indicator_deployments.return_value = None
    result = reporter.report_indicator_deployments(
        [DeploymentReport(indicator_id="a", status="deployed")]
    )
    assert result.errors[0].message == "Reports not accepted by OpenCTI"

    pycti_helper.report_indicator_deployments.return_value = {"errors": []}
    result = reporter.report_indicator_deployments(
        [DeploymentReport(indicator_id="a", status="deployed")]
    )
    assert [report.indicator_id for report in result.unsent] == ["a"]


@pytest.mark.parametrize(
    "response",
    [
        {"data": None},
        {"data": {"indicatorReportDeployments": None}},
        {"data": {"indicatorReportDeployments": {"errors": []}}},
    ],
)
def test_a_batch_answered_without_its_result_is_sent_again(
    graphql_helper, make_reporter, router, response
):
    """An HTTP success without the batch result never drops the queued reports."""
    router.handlers["IndicatorReportDeployments("] = response
    reporter = make_reporter(graphql_helper)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="removed"))

    result = reporter.flush()

    assert [report.indicator_id for report in result.unsent] == ["a"]
    assert list(reporter._buffer) == ["a"]


@pytest.mark.parametrize(
    "response", [{"data": None}, {"data": {"indicatorReportDeployment": None}}]
)
def test_a_single_report_answered_without_its_result_is_undelivered(
    graphql_helper, make_reporter, router, router_factory, response
):
    router.handlers.update(
        router_factory(mutations=("indicatorReportDeployment",)).handlers
    )
    router.handlers["IndicatorReportDeployment("] = response
    reporter = make_reporter(graphql_helper)

    result = reporter.report_indicator_deployments(
        [DeploymentReport(indicator_id="a", status="active")]
    )

    assert [report.indicator_id for report in result.unsent] == ["a"]


def test_a_hit_report_answered_without_its_result_is_undelivered(
    graphql_helper, make_reporter, router
):
    router.handlers["IndicatorReportHits("] = {"data": {"indicatorReportHits": None}}
    reporter = make_reporter(graphql_helper)

    assert (
        reporter.report_indicator_hits_outcome("a", 1, last_hit="2026-10-03T10:00:00Z")
        == REPORT_UNSENT
    )


# --- hits ----------------------------------------------------------------------------


def test_report_indicator_hits_with_graphql(graphql_helper, make_reporter, router, ids):
    """Hits send the contract mutation."""
    reporter = make_reporter(graphql_helper)

    assert reporter.report_indicator_hits(
        ids.indicator,
        3,
        last_hit=datetime(2026, 10, 3, 10, tzinfo=UTC),
        first_hit="2026-10-03T08:00:00Z",
    )
    assert reporter.report_indicator_hits(ids.indicator, 1)

    assert router.calls_of("IndicatorReportHits(") == [
        {
            "indicatorId": ids.indicator,
            "platformId": ids.platform,
            "count": 3,
            "lastHit": "2026-10-03T10:00:00.000Z",
            "firstHit": "2026-10-03T08:00:00.000Z",
        },
        {"indicatorId": ids.indicator, "platformId": ids.platform, "count": 1},
    ]


def test_report_indicator_hits_with_the_pycti_helper(pycti_helper, make_reporter, ids):
    """Hits use the pycti helper when available."""
    reporter = make_reporter(pycti_helper)

    assert reporter.report_indicator_hits(
        ids.indicator, 2, last_hit="2026-10-03T10:00:00Z"
    )

    pycti_helper.report_indicator_hits.assert_called_once_with(
        indicator_id=ids.indicator,
        platform_id=ids.platform,
        count=2,
        last_hit="2026-10-03T10:00:00.000Z",
        first_hit=None,
    )


@pytest.mark.parametrize(("indicator_id", "count"), [("", 1), ("indicator-id", 0)])
def test_report_indicator_hits_ignores_empty_reports(
    graphql_helper, make_reporter, router, indicator_id, count
):
    """Empty hit reports are never sent."""
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_hits(indicator_id, count) is False
    assert router.calls == []


def test_report_indicator_hits_on_a_platform_without_hits(
    graphql_helper, make_reporter, router, router_factory
):
    """Platforms without ``indicatorReportHits`` make hits a no-op."""
    router.handlers.update(
        router_factory(mutations=("indicatorReportDeployment",)).handlers
    )
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_hits("indicator-id", 1) is False


def test_report_indicator_hits_errors_never_raise(
    graphql_helper, make_reporter, router
):
    """GraphQL errors of hit reports are logged as warnings."""
    router.handlers["IndicatorReportHits("] = ValueError("boom")
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_hits("indicator-id", 1) is False
    graphql_helper.connector_logger.warning.assert_called_once()


@pytest.mark.parametrize(
    ("error", "outcome"),
    [
        (
            ValueError({"name": "FUNCTIONAL_ERROR", "error_message": "gone"}),
            REPORT_REJECTED,
        ),
        (
            ValueError(
                {"name": "FUNCTIONAL_ERROR", "error_message": "Too many requests"}
            ),
            REPORT_UNSENT,
        ),
        (ValueError("Connection refused"), REPORT_UNSENT),
    ],
)
def test_report_indicator_hits_outcome_tells_rejections_from_undelivered_calls(
    graphql_helper, make_reporter, router, error, outcome
):
    router.handlers["IndicatorReportHits("] = error
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_hits_outcome("indicator-id", 1) == outcome


def test_report_indicator_hits_outcome(
    graphql_helper, pycti_helper, make_reporter, router, router_factory
):
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_hits_outcome("indicator-id", 1) == REPORT_SENT
    assert reporter.report_indicator_hits_outcome("indicator-id", 0) == REPORT_REJECTED

    pycti_helper.report_indicator_hits.return_value = None
    assert (
        make_reporter(pycti_helper).report_indicator_hits_outcome("indicator-id", 1)
        == REPORT_UNSENT
    )

    router.handlers.update(
        router_factory(mutations=("indicatorReportDeployment",)).handlers
    )
    assert (
        make_reporter(graphql_helper).report_indicator_hits_outcome("indicator-id", 1)
        == REPORT_REJECTED
    )


def test_report_indicator_hits_outcome_while_the_write_back_is_awaited(
    graphql_helper, make_reporter, router
):
    """OpenCTI unreachable at detection time: the report can be sent later."""
    router.handlers["DeploymentWriteBackFeatures"] = ValueError("Connection refused")
    reporter = make_reporter(graphql_helper)
    assert reporter.report_indicator_hits_outcome("indicator-id", 1) == REPORT_UNSENT


# --- listing ---------------------------------------------------------------------------


def test_list_indicator_deployments_paginates(
    graphql_helper, make_reporter, router, node_factory, ids
):
    """Deployments are listed page by page with the status filter."""
    pages = iter(
        [
            {
                "data": {
                    "stixCoreRelationships": {
                        "edges": [
                            {"node": node_factory(indicator_id="a")},
                            {"node": {"id": "unreadable", "from": None}},
                        ],
                        "pageInfo": {"endCursor": "cursor-1", "hasNextPage": True},
                    }
                }
            },
            {
                "data": {
                    "stixCoreRelationships": {
                        "edges": [{"node": node_factory(indicator_id="b")}],
                        "pageInfo": {"endCursor": "cursor-2", "hasNextPage": False},
                    }
                }
            },
        ]
    )
    router.handlers["IndicatorDeploymentsOfPlatform"] = lambda _variables: next(pages)
    reporter = make_reporter(graphql_helper)

    deployments = list(
        reporter.list_indicator_deployments(["deployed", DeploymentStatus.ACTIVE])
    )

    assert [deployment.indicator_id for deployment in deployments] == ["a", "b"]
    calls = router.calls_of("IndicatorDeploymentsOfPlatform")
    assert calls[0] == {
        "relationshipTypes": ["deployed-on"],
        "toId": [ids.platform],
        "first": 500,
        "after": None,
        "filters": {
            "mode": "and",
            "filterGroups": [],
            "filters": [{"key": "deployment_status", "values": ["deployed", "active"]}],
        },
    }
    assert calls[1]["after"] == "cursor-1"


def test_list_indicator_deployments_without_status_filter(
    graphql_helper, make_reporter, router
):
    """All statuses are listed without a filter; an empty last page ends the listing."""
    reporter = make_reporter(graphql_helper)
    assert list(reporter.list_indicator_deployments()) == []
    assert router.calls_of("IndicatorDeploymentsOfPlatform")[0]["filters"] is None


def _page(edges, page_info):
    return {"data": {"stixCoreRelationships": {"edges": edges, "pageInfo": page_info}}}


_LAST_PAGE = {"endCursor": None, "hasNextPage": False}


@pytest.mark.parametrize(
    "response",
    [
        None,
        {"data": None},
        {"data": {"stixCoreRelationships": None}},
        {"data": {"stixCoreRelationships": {"pageInfo": _LAST_PAGE}}},
        _page(None, _LAST_PAGE),
        _page([], None),
        _page(["not an edge"], _LAST_PAGE),
        _page([{"node": None}], _LAST_PAGE),
        _page([], {"endCursor": None}),
        _page([], {"endCursor": None, "hasNextPage": True}),
        _page([], {"endCursor": "", "hasNextPage": True}),
    ],
    ids=[
        "no response",
        "null data",
        "null connection",
        "no edges",
        "null edges",
        "null page information",
        "malformed edge",
        "edge without its relationship",
        "no hasNextPage",
        "next page without cursor",
        "next page with an empty cursor",
    ],
)
def test_list_indicator_deployments_rejects_a_malformed_page(
    graphql_helper, make_reporter, router, response
):
    """A page that is not a complete connection is never read as empty or as the last page."""
    router.handlers["IndicatorDeploymentsOfPlatform"] = response
    reporter = make_reporter(graphql_helper)
    with pytest.raises(DeploymentListingError, match="OpenCTI"):
        list(reporter.list_indicator_deployments())


def test_list_indicator_deployments_rejects_a_cursor_already_followed(
    graphql_helper, make_reporter, router, node_factory
):
    """A cursor pointing back to a page already read never loops nor ends the listing."""
    pages = iter(
        [
            _page(
                [{"node": node_factory(indicator_id="a")}],
                {"endCursor": "cursor-1", "hasNextPage": True},
            ),
            _page(
                [{"node": node_factory(indicator_id="b")}],
                {"endCursor": "cursor-2", "hasNextPage": True},
            ),
            _page(
                [{"node": node_factory(indicator_id="a")}],
                {"endCursor": "cursor-1", "hasNextPage": True},
            ),
        ]
    )
    router.handlers["IndicatorDeploymentsOfPlatform"] = lambda _variables: next(pages)
    reporter = make_reporter(graphql_helper)

    with pytest.raises(DeploymentListingError, match="already followed"):
        list(reporter.list_indicator_deployments())
    assert len(router.calls_of("IndicatorDeploymentsOfPlatform")) == 3


def test_list_indicator_deployments_raises_on_error(
    graphql_helper, make_reporter, router
):
    """A failing page raises ``DeploymentListingError``."""
    router.handlers["IndicatorDeploymentsOfPlatform"] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper)
    with pytest.raises(DeploymentListingError, match="unreachable"):
        list(reporter.list_indicator_deployments())


def test_list_indicator_deployments_when_unavailable(
    graphql_helper, make_reporter, router, router_factory
):
    """Nothing is listed on platforms without the write-back."""
    router.handlers.update(router_factory(mutations=()).handlers)
    reporter = make_reporter(graphql_helper)
    assert list(reporter.list_indicator_deployments()) == []


def test_list_indicator_deployments_never_uses_the_pycti_helper(
    pycti_helper, make_reporter, router, node_factory
):
    """The pycti listing ends quietly on a failed page: the paginated query is used."""
    pages = iter(
        [
            {
                "data": {
                    "stixCoreRelationships": {
                        "edges": [{"node": node_factory(indicator_id="a")}],
                        "pageInfo": {"endCursor": "cursor-1", "hasNextPage": True},
                    }
                }
            },
            ConnectionError("unreachable"),
        ]
    )
    router.handlers["IndicatorDeploymentsOfPlatform"] = lambda _variables: next(pages)
    reporter = make_reporter(pycti_helper)

    listed = []
    with pytest.raises(DeploymentListingError, match="unreachable"):
        for deployment in reporter.list_indicator_deployments(["pending"]):
            listed.append(deployment.indicator_id)

    assert listed == ["a"]
    pycti_helper.list_indicator_deployments.assert_not_called()


# --- queued reports ------------------------------------------------------------------------


def test_stream_reports_are_coalesced_and_flushed(
    graphql_helper, make_reporter, router, indicator_factory, ids
):
    """Queued reports keep the latest status per indicator, flushed in one batch."""
    reporter = make_reporter(graphql_helper)
    indicator = indicator_factory()
    other = indicator_factory(indicator_id="other-id")

    assert reporter.report_pushed(indicator, external_id="vendor-1")
    assert reporter.report_push_failed(other, ValueError("bad pattern"))
    assert reporter.report_removed(indicator, external_id="vendor-1")
    assert router.calls_of("IndicatorReportDeployments(") == []

    result = reporter.flush()

    reports = router.calls_of("IndicatorReportDeployments(")[0]["reports"]
    assert reports == [
        {
            "indicatorId": "other-id",
            "status": "failed",
            "metadata": {"error_message": "bad pattern"},
        },
        {"indicatorId": ids.indicator, "status": "removed", "externalId": "vendor-1"},
    ]
    assert result.processed == 2
    assert reporter.flush() == DeploymentBatchResult()


def test_stream_reports_ignore_non_indicators(
    graphql_helper, make_reporter, indicator_factory
):
    """Only indicators get deployment reports."""
    reporter = make_reporter(graphql_helper)
    assert reporter.report_pushed({"type": "ipv4-addr", "id": "ipv4-addr--1"}) is False
    assert reporter.report_pushed({"type": "indicator"}) is False


def test_stream_reports_when_disabled(
    graphql_helper, make_reporter, options, indicator_factory
):
    """Disabled write-back queues nothing."""
    reporter = make_reporter(graphql_helper, replace(options, reporting_enabled=False))
    assert reporter.report_pushed(indicator_factory()) is False
    assert (
        reporter.enqueue(DeploymentReport(indicator_id="a", status="active")) is False
    )


def test_stream_reports_on_a_platform_known_to_be_unsupported(
    graphql_helper, make_reporter, router, router_factory, indicator_factory
):
    """Nothing is queued once the platform is known not to support the write-back."""
    router.handlers.update(router_factory(mutations=()).handlers)
    reporter = make_reporter(graphql_helper)
    reporter.start()
    assert reporter.report_pushed(indicator_factory()) is False


def test_stream_failure_messages_are_bounded(
    graphql_helper, make_reporter, router, indicator_factory
):
    """Long vendor errors are truncated; empty errors use the exception type."""
    reporter = make_reporter(graphql_helper)
    reporter.report_push_failed(indicator_factory(indicator_id="a"), "x" * 5000)
    reporter.report_push_failed(indicator_factory(indicator_id="b"), TimeoutError())
    reporter.flush()

    reports = router.calls_of("IndicatorReportDeployments(")[0]["reports"]
    message = reports[0]["metadata"]["error_message"]
    assert len(message) == MAX_ERROR_MESSAGE_LENGTH
    assert message.endswith("...")
    assert reports[1]["metadata"]["error_message"] == "TimeoutError"


def test_queue_flushes_at_the_batch_size(graphql_helper, make_reporter, router):
    """Reaching 500 queued reports flushes immediately."""
    reporter = make_reporter(graphql_helper)
    for index in range(MAX_BATCH_SIZE):
        reporter.enqueue(DeploymentReport(indicator_id=f"i-{index}", status="active"))
    calls = router.calls_of("IndicatorReportDeployments(")
    assert [len(call["reports"]) for call in calls] == [MAX_BATCH_SIZE]


def test_queue_flushes_on_a_timer(graphql_helper, make_reporter, router):
    """Queued reports are flushed after the flush interval."""
    flushed = threading.Event()
    batch_handler = router.handlers["IndicatorReportDeployments("]

    def handler(variables):
        flushed.set()
        return batch_handler(variables)

    router.handlers["IndicatorReportDeployments("] = handler
    reporter = make_reporter(graphql_helper, flush_interval=0.01)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="active"))

    assert flushed.wait(5)


def test_timer_flush_errors_never_raise(graphql_helper, make_reporter, monkeypatch):
    """Errors of a timer flush are logged."""
    reporter = make_reporter(graphql_helper)
    monkeypatch.setattr(reporter, "flush", MagicMock(side_effect=RuntimeError("boom")))
    reporter._flush_on_timer()
    graphql_helper.connector_logger.warning.assert_called_once()


def test_close_flushes_and_stops_queueing(graphql_helper, make_reporter, router):
    """Closing flushes the queue and rejects later reports."""
    reporter = make_reporter(graphql_helper)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="active"))
    reporter.close()
    assert len(router.calls_of("IndicatorReportDeployments(")) == 1
    assert (
        reporter.enqueue(DeploymentReport(indicator_id="b", status="active")) is False
    )


def test_queued_reports_wait_for_the_feature_detection(
    graphql_helper, make_reporter, router
):
    """Reports stay queued while the detection is retried, then are sent."""
    clock = Clock()
    detection = router.handlers["DeploymentWriteBackFeatures"]
    router.handlers["DeploymentWriteBackFeatures"] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper, monotonic=clock, retry_delay=60.0)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="deployed"))
    reporter.enqueue(DeploymentReport(indicator_id="b", status="deployed"))

    assert reporter.flush() == DeploymentBatchResult()
    assert router.calls_of("IndicatorReportDeployments(") == []
    assert reporter._flush_timer is not None

    reporter.enqueue(DeploymentReport(indicator_id="a", status="removed"))
    router.handlers["DeploymentWriteBackFeatures"] = detection
    clock.now += 61

    result = reporter.flush()

    reports = router.calls_of("IndicatorReportDeployments(")[0]["reports"]
    assert reports == [
        {"indicatorId": "b", "status": "deployed"},
        {"indicatorId": "a", "status": "removed"},
    ]
    assert result.processed == 2


def test_queued_reports_wait_for_the_security_platform(
    graphql_helper, make_reporter, router, ids
):
    """Reports stay queued while the security platform resolution is retried."""
    clock = Clock()
    router.handlers["DeploymentSecurityPlatformAdd"] = {"data": None}
    reporter = make_reporter(graphql_helper, monotonic=clock, retry_delay=60.0)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="deployed"))

    reporter.flush()
    assert router.calls_of("IndicatorReportDeployments(") == []

    router.handlers["DeploymentSecurityPlatformAdd"] = {
        "data": {"securityPlatformAdd": {"id": ids.platform}}
    }
    clock.now += 61
    assert reporter.flush().processed == 1


def test_queued_reports_are_dropped_on_unsupported_platforms(
    graphql_helper, make_reporter, router, router_factory
):
    """Platforms without the write-back drop the queued reports."""
    router.handlers.update(router_factory(mutations=()).handlers)
    reporter = make_reporter(graphql_helper)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="deployed"))

    assert reporter.flush() == DeploymentBatchResult()
    assert reporter._buffer == {}


def test_queued_reports_are_bounded_while_waiting(
    graphql_helper, make_reporter, router, monkeypatch
):
    """The oldest reports are dropped beyond the queue limit."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.MAX_QUEUED_REPORTS", 2
    )
    router.handlers["DeploymentWriteBackFeatures"] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper)
    for indicator_id in ("a", "b", "c"):
        reporter.enqueue(DeploymentReport(indicator_id=indicator_id, status="deployed"))

    reporter.flush()

    assert list(reporter._buffer) == ["b", "c"]
    assert any(
        "dropping" in call.args[0]
        for call in graphql_helper.connector_logger.warning.call_args_list
    )


def test_full_queue_does_not_flush_while_waiting(
    graphql_helper, make_reporter, router, monkeypatch
):
    """While waiting for the write-back, only the timer retries the flush."""
    monkeypatch.setattr(
        "connectors_sdk.connectors.stream.deployment.reporter.MAX_BATCH_SIZE", 2
    )
    router.handlers["DeploymentWriteBackFeatures"] = ConnectionError("unreachable")
    reporter = make_reporter(graphql_helper)
    reporter.enqueue(DeploymentReport(indicator_id="a", status="deployed"))
    reporter.enqueue(DeploymentReport(indicator_id="b", status="deployed"))
    detections = len(router.calls_of("DeploymentWriteBackFeatures"))

    reporter.enqueue(DeploymentReport(indicator_id="c", status="deployed"))

    assert len(router.calls_of("DeploymentWriteBackFeatures")) == detections
    assert list(reporter._buffer) == ["a", "b", "c"]


def test_invalid_report_fields_are_logged(graphql_helper, make_reporter):
    """Unexpected report fields are logged and ignored."""
    reporter = make_reporter(graphql_helper)
    assert reporter._build_report(indicator_id="a", status="active", unknown=1) is None
    graphql_helper.connector_logger.warning.assert_called_once()
