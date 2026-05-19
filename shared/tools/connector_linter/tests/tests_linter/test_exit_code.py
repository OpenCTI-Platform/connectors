"""Tests for exit-code semantics."""

from connector_linter.models import (
    CheckFinding,
    CheckResult,
    ConnectorContext,
    Severity,
)
from connector_linter.registry import CheckRegistry
from connector_linter.runner import run_checks


def _has_errors(results: list[CheckResult]) -> bool:
    """Replicate the exit-code logic from __main__.py."""
    return any(r.severity == Severity.ERROR for r in results)


class TestExitCode:
    def test_all_pass_exit_0(self, dummy_checks, minimal_connector):
        assert not _has_errors(run_checks(minimal_connector, select=["VC901", "VC902"]))

    def test_error_fail_exit_1(self, dummy_checks, minimal_connector):
        assert _has_errors(run_checks(minimal_connector, select=["VC903"]))

    def test_warning_only_exit_0(self, _clean_registry, minimal_connector):
        @CheckRegistry.register(
            code="VC960",
            name="test-warn-fail",
            description="Warning that fails",
            severity=Severity.WARNING,
        )
        def _warn(ctx: ConnectorContext) -> list[CheckFinding]:
            return [CheckFinding(message="not great", severity=Severity.WARNING)]

        assert not _has_errors(run_checks(minimal_connector, select=["VC960"]))

    def test_mixed_with_error_exit_1(self, dummy_checks, minimal_connector):
        assert _has_errors(
            run_checks(minimal_connector, select=["VC901", "VC902", "VC903"])
        )

    def test_empty_results_exit_0(self, _clean_registry, minimal_connector):
        assert not _has_errors(run_checks(minimal_connector, select=["VC000"]))
