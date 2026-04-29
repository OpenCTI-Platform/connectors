"""Tests for exit-code semantics.

Rules:
- exit 1 if any ERROR-severity check FAILED
- exit 0 otherwise (all pass, or only warnings/info fail)
"""

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
        results = run_checks(minimal_connector, select=["VC901", "VC902"])
        assert not _has_errors(results)

    def test_error_fail_exit_1(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC903"])
        assert _has_errors(results)

    def test_warning_only_exit_0(self, _clean_registry, minimal_connector):
        @CheckRegistry.register(
            code="VC960",
            name="test-warn-fail",
            description="Warning that fails",
            severity=Severity.WARNING,
        )
        def _warn(ctx: ConnectorContext) -> list[CheckFinding]:
            return [CheckFinding(message="not great", severity=Severity.WARNING)]

        results = run_checks(minimal_connector, select=["VC960"])
        assert not _has_errors(results)

    def test_mixed_with_error_exit_1(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC901", "VC902", "VC903"])
        # VC903 fails with ERROR severity → exit 1
        assert _has_errors(results)

    def test_empty_results_exit_0(self, _clean_registry, minimal_connector):
        # No checks selected → no results → exit 0
        results = run_checks(minimal_connector, select=["VC000"])
        assert not _has_errors(results)
