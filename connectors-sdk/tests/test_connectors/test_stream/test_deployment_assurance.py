# pragma: no cover  # do not compute coverage on test files
# type: ignore
"""Tests of the dissemination assurance facade."""

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock

from connectors_sdk.connectors.stream.deployment import (
    DeploymentAssurance,
    DeploymentReconciler,
    DeploymentReporter,
    DeploymentVendorAdapter,
    SecurityPlatformConfig,
)


class _Adapter(DeploymentVendorAdapter):
    def list_vendor_indicators(self):
        return []

    def remove_vendor_indicator(self, vendor_indicator, deployment):
        return None

    def push_indicator(self, stix_indicator):
        return None


def test_from_settings_without_adapter(graphql_helper, no_atexit):
    """Without adapter, only push outcomes are reported."""
    settings = SimpleNamespace(security_platform=SecurityPlatformConfig(name="My EDR"))
    assurance = DeploymentAssurance.from_settings(
        graphql_helper, settings, reporter_kwargs={"flush_interval": 1.0}
    )
    assert isinstance(assurance.reporter, DeploymentReporter)
    assert assurance.reconciler is None
    assert assurance.enabled is True
    assert assurance.start() is True
    assurance.stop()


def test_from_options_with_adapter(graphql_helper, options, no_atexit):
    """With an adapter, the reconciliation is wired and started."""
    assurance = DeploymentAssurance.from_options(
        graphql_helper, options, _Adapter(), initial_delay=3600.0
    )
    assert isinstance(assurance.reconciler, DeploymentReconciler)

    assert assurance.start() is True
    assert assurance.reconciler._thread.is_alive()

    assurance.stop(timeout=5)
    assert not assurance.reconciler._thread.is_alive()


def test_start_does_not_schedule_the_reconciliation_when_disabled(
    graphql_helper, options, no_atexit
):
    """A disabled write-back starts nothing."""
    assurance = DeploymentAssurance.from_options(
        graphql_helper, replace(options, reporting_enabled=False), _Adapter()
    )
    assert assurance.start() is False
    assert assurance.reconciler._thread is None


def test_stream_reports_are_delegated_to_the_reporter(indicator_factory):
    """Stream report helpers and flush delegate to the reporter."""
    reporter = MagicMock(spec=DeploymentReporter)
    assurance = DeploymentAssurance(reporter)
    indicator = indicator_factory()
    error = ValueError("rejected")

    assurance.report_pushed(
        indicator, external_id="v", deployed_at="2026-10-03T00:00:00Z"
    )
    assurance.report_push_failed(indicator, error, external_id="v")
    assurance.report_removed(
        indicator, external_id="v", removed_at="2026-10-03T01:00:00Z"
    )
    assurance.flush()

    reporter.report_pushed.assert_called_once_with(
        indicator, external_id="v", deployed_at="2026-10-03T00:00:00Z"
    )
    reporter.report_push_failed.assert_called_once_with(
        indicator, error, external_id="v"
    )
    reporter.report_removed.assert_called_once_with(
        indicator, external_id="v", removed_at="2026-10-03T01:00:00Z"
    )
    reporter.flush.assert_called_once_with()
