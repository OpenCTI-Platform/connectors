"""Tests for run_checks: select/ignore, exception handling, noqa integration."""

from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry
from connector_linter.runner import run_checks


class TestSelectIgnore:
    """--select and --ignore filter which checks are executed."""

    def test_select_exact_code(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC901"])
        codes = {r.code for r in results}
        assert codes == {"VC901"}

    def test_select_prefix(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC9xx"])
        codes = {r.code for r in results}
        assert codes == {"VC901", "VC902", "VC903"}

    def test_ignore_exact_code(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC9xx"], ignore=["VC903"])
        codes = {r.code for r in results}
        assert "VC903" not in codes
        assert "VC901" in codes

    def test_ignore_prefix(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC9xx"], ignore=["VC90"])
        codes = {r.code for r in results}
        assert codes == set()

    def test_select_and_ignore_combined(self, dummy_checks, minimal_connector):
        results = run_checks(
            minimal_connector,
            select=["VC901", "VC902", "VC903"],
            ignore=["VC902"],
        )
        codes = {r.code for r in results}
        assert codes == {"VC901", "VC903"}


class TestCheckExecution:
    """Checks are executed and produce correct results."""

    def test_severity_propagation(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC901", "VC902"])
        by_code = {r.code: r for r in results}
        assert by_code["VC901"].severity == Severity.INFO
        assert by_code["VC902"].severity == Severity.WARNING

    def test_suggestion_propagation(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC903"])
        assert results[0].suggestion == "fix it"

    def test_deterministic_order(self, dummy_checks, minimal_connector):
        results = run_checks(minimal_connector, select=["VC9xx"])
        codes = [r.code for r in results]
        assert codes == sorted(codes)


class TestExceptionHandling:
    """Checks that raise exceptions produce a FAIL result, not a crash."""

    def test_exception_yields_fail(self, _clean_registry, minimal_connector):
        @CheckRegistry.register(
            code="VC999",
            name="test-boom",
            description="Raises on purpose",
            severity=Severity.ERROR,
        )
        def _boom(ctx: ConnectorContext) -> list[CheckFinding]:
            raise RuntimeError("kaboom")

        results = run_checks(minimal_connector, select=["VC999"])
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
        assert "RuntimeError" in results[0].message
        assert "kaboom" in results[0].message

    def test_exception_always_error_severity(self, _clean_registry, minimal_connector):
        """A crashing WARNING check is escalated to ERROR so CI won't silently pass."""

        @CheckRegistry.register(
            code="VC998",
            name="test-warn-boom",
            description="Warning check that crashes",
            severity=Severity.WARNING,
        )
        def _boom(ctx: ConnectorContext) -> list[CheckFinding]:
            raise ValueError("oops")

        results = run_checks(minimal_connector, select=["VC998"])
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR


class TestNoqaIntegration:
    """Noqa directives suppress results when enabled."""

    def test_noqa_suppresses_result(self, _clean_registry, minimal_connector):
        src_file = minimal_connector / "src" / "target.py"
        src_file.write_text("x = 1  # noqa: VC950\n", encoding="utf-8")

        @CheckRegistry.register(
            code="VC950",
            name="test-noqa",
            description="Check that can be noqa'd",
            severity=Severity.ERROR,
        )
        def _check(ctx: ConnectorContext) -> list[CheckFinding]:
            return [
                CheckFinding(
                    message="flagged",
                    severity=Severity.ERROR,
                    file_path=ctx.path / "src" / "target.py",
                    line=1,
                )
            ]

        results = run_checks(minimal_connector, select=["VC950"], disable_noqa=False)
        assert len(results) == 0

    def test_disable_noqa_keeps_result(self, _clean_registry, minimal_connector):
        src_file = minimal_connector / "src" / "target.py"
        src_file.write_text("x = 1  # noqa: VC950\n", encoding="utf-8")

        @CheckRegistry.register(
            code="VC950",
            name="test-noqa-disabled",
            description="Check with noqa disabled",
            severity=Severity.ERROR,
        )
        def _check(ctx: ConnectorContext) -> list[CheckFinding]:
            return [
                CheckFinding(
                    message="flagged",
                    severity=Severity.ERROR,
                    file_path=ctx.path / "src" / "target.py",
                    line=1,
                )
            ]

        results = run_checks(minimal_connector, select=["VC950"], disable_noqa=True)
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR

    def test_bare_noqa_suppresses_all(self, _clean_registry, minimal_connector):
        src_file = minimal_connector / "src" / "target.py"
        src_file.write_text("x = 1  # noqa\n", encoding="utf-8")

        @CheckRegistry.register(
            code="VC951",
            name="test-bare-noqa",
            description="Bare noqa suppresses everything",
            severity=Severity.ERROR,
        )
        def _check(ctx: ConnectorContext) -> list[CheckFinding]:
            return [
                CheckFinding(
                    message="flagged",
                    severity=Severity.ERROR,
                    file_path=ctx.path / "src" / "target.py",
                    line=1,
                )
            ]

        results = run_checks(minimal_connector, select=["VC951"], disable_noqa=False)
        assert len(results) == 0

    def test_noqa_wrong_code_no_suppress(self, _clean_registry, minimal_connector):
        src_file = minimal_connector / "src" / "target.py"
        src_file.write_text("x = 1  # noqa: VC999\n", encoding="utf-8")

        @CheckRegistry.register(
            code="VC952",
            name="test-noqa-mismatch",
            description="Noqa with different code does not suppress",
            severity=Severity.ERROR,
        )
        def _check(ctx: ConnectorContext) -> list[CheckFinding]:
            return [
                CheckFinding(
                    message="flagged",
                    severity=Severity.ERROR,
                    file_path=ctx.path / "src" / "target.py",
                    line=1,
                )
            ]

        results = run_checks(minimal_connector, select=["VC952"], disable_noqa=False)
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
