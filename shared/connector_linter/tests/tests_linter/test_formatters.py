"""Tests for formatters: text, JSON, and GitHub Actions output."""

import json
from io import StringIO
from pathlib import Path

from connector_linter.formatters import format_github, format_json, format_text
from connector_linter.models import CheckResult, Severity


def _make_result(
    code: str = "VC901",
    name: str = "test-check",
    message: str = "everything ok",
    severity: Severity = Severity.ERROR,
    passed: bool = True,
    file_path: Path | None = None,
    line: int | None = None,
    suggestion: str | None = None,
) -> CheckResult:
    return CheckResult(
        code=code,
        name=name,
        message=message,
        severity=severity,
        passed=passed,
        file_path=file_path,
        line=line,
        suggestion=suggestion,
    )


class TestFormatText:
    """format_text: human-readable output."""

    def test_failed_always_shown(self, tmp_path: Path):
        results = [_make_result(passed=False, message="broken")]
        buf = StringIO()
        format_text(results, tmp_path, buf)
        output = buf.getvalue()
        assert "VC901" in output
        assert "FAIL" in output
        assert "broken" in output

    def test_passed_shown_normally(self, tmp_path: Path):
        results = [_make_result(passed=True, message="looks good")]
        buf = StringIO()
        format_text(results, tmp_path, buf, quiet=False)
        output = buf.getvalue()
        assert "PASS" in output
        assert "looks good" in output

    def test_quiet_hides_passed_errors(self, tmp_path: Path):
        """--quiet suppresses passed checks with ERROR severity."""
        results = [_make_result(passed=True, severity=Severity.ERROR, message="ok")]
        buf = StringIO()
        format_text(results, tmp_path, buf, quiet=True)
        output = buf.getvalue()
        # The "ok" message should NOT appear in a result line (score summary is fine)
        lines = [l for l in output.splitlines() if "VC901" in l]
        assert len(lines) == 0

    def test_quiet_shows_passed_warnings(self, tmp_path: Path):
        """--quiet still shows passed WARNING checks."""
        results = [
            _make_result(
                passed=True, severity=Severity.WARNING, message="advisory note"
            )
        ]
        buf = StringIO()
        format_text(results, tmp_path, buf, quiet=True)
        output = buf.getvalue()
        assert "advisory note" in output
        assert "WARN" in output

    def test_suggestion_displayed(self, tmp_path: Path):
        results = [
            _make_result(passed=False, message="bad", suggestion="do this instead")
        ]
        buf = StringIO()
        format_text(results, tmp_path, buf)
        output = buf.getvalue()
        assert "do this instead" in output
        assert "↳" in output

    def test_score_line(self, tmp_path: Path):
        results = [
            _make_result(passed=True, message="ok1"),
            _make_result(code="VC902", passed=False, message="nope"),
        ]
        buf = StringIO()
        format_text(results, tmp_path, buf)
        output = buf.getvalue()
        assert "Score: 1/2" in output
        assert "50%" in output

    def test_abspath_mode(self, tmp_path: Path):
        results = [
            _make_result(
                passed=False,
                file_path=Path("src/main.py"),
                message="issue",
            )
        ]
        buf = StringIO()
        format_text(results, tmp_path, buf, abspath=True)
        output = buf.getvalue()
        # Should contain the resolved absolute path
        assert str(tmp_path.resolve()) in output


class TestFormatJson:
    """format_json: machine-readable JSON output."""

    def test_valid_json(self, tmp_path: Path):
        results = [
            _make_result(passed=True, message="ok"),
            _make_result(code="VC902", passed=False, message="fail"),
        ]
        buf = StringIO()
        format_json(results, tmp_path, buf)
        data = json.loads(buf.getvalue())
        assert "connector" in data
        assert "summary" in data
        assert "results" in data

    def test_summary_counts(self, tmp_path: Path):
        results = [
            _make_result(passed=True),
            _make_result(code="VC902", passed=False),
            _make_result(code="VC903", passed=True),
        ]
        buf = StringIO()
        format_json(results, tmp_path, buf)
        data = json.loads(buf.getvalue())
        assert data["summary"]["total"] == 3
        assert data["summary"]["passed"] == 2
        assert data["summary"]["failed"] == 1

    def test_result_fields(self, tmp_path: Path):
        results = [
            _make_result(
                code="VC901",
                name="test-check",
                message="found it",
                severity=Severity.WARNING,
                passed=False,
                file_path=Path("src/main.py"),
                line=42,
                suggestion="try harder",
            )
        ]
        buf = StringIO()
        format_json(results, tmp_path, buf)
        data = json.loads(buf.getvalue())
        r = data["results"][0]
        assert r["code"] == "VC901"
        assert r["name"] == "test-check"
        assert r["message"] == "found it"
        assert r["severity"] == "warning"
        assert r["passed"] is False
        assert r["line"] == 42
        assert r["suggestion"] == "try harder"

    def test_file_path_absolute(self, tmp_path: Path):
        results = [
            _make_result(file_path=Path("src/main.py"), passed=True, message="ok")
        ]
        buf = StringIO()
        format_json(results, tmp_path, buf)
        data = json.loads(buf.getvalue())
        fp = data["results"][0]["file_path"]
        assert Path(fp).is_absolute()

    def test_score_pct(self, tmp_path: Path):
        results = [
            _make_result(passed=True),
            _make_result(code="VC902", passed=True),
        ]
        buf = StringIO()
        format_json(results, tmp_path, buf)
        data = json.loads(buf.getvalue())
        assert data["summary"]["score_pct"] == 100.0


class TestFormatGithub:
    """format_github: GitHub Actions annotations."""

    def test_error_annotation(self, tmp_path: Path):
        results = [
            _make_result(
                passed=False,
                severity=Severity.ERROR,
                message="broken",
                file_path=Path("src/main.py"),
                line=10,
            )
        ]
        buf = StringIO()
        format_github(results, tmp_path, buf)
        output = buf.getvalue()
        assert output.startswith("::error")
        assert "line=10" in output
        assert "VC901: broken" in output

    def test_warning_annotation(self, tmp_path: Path):
        results = [
            _make_result(
                passed=False,
                severity=Severity.WARNING,
                message="risky",
                file_path=Path("src/main.py"),
            )
        ]
        buf = StringIO()
        format_github(results, tmp_path, buf)
        output = buf.getvalue()
        assert output.startswith("::warning")

    def test_passed_checks_skipped(self, tmp_path: Path):
        results = [_make_result(passed=True, message="all good")]
        buf = StringIO()
        format_github(results, tmp_path, buf)
        assert buf.getvalue() == ""

    def test_default_line_number(self, tmp_path: Path):
        results = [
            _make_result(
                passed=False,
                message="no line",
                file_path=Path("src/main.py"),
                line=None,
            )
        ]
        buf = StringIO()
        format_github(results, tmp_path, buf)
        assert "line=1" in buf.getvalue()
