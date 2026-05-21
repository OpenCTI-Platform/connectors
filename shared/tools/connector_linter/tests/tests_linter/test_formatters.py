"""Tests for formatters: text, JSON, and GitHub Actions output."""

import json
from io import StringIO
from pathlib import Path

import pytest
from connector_linter.formatters import format_github, format_json, format_text
from connector_linter.models import CheckResult, Severity


def _make_result(
    code: str = "VC901",
    name: str = "test-check",
    message: str = "everything ok",
    severity: Severity = Severity.INFO,
    file_path: Path | None = None,
    line: int | None = None,
    suggestion: str | None = None,
) -> CheckResult:
    return CheckResult(
        code=code,
        name=name,
        message=message,
        severity=severity,
        file_path=file_path,
        line=line,
        suggestion=suggestion,
    )


class TestFormatText:
    """format_text: human-readable output."""

    def test_failed_always_shown(self, tmp_path: Path):
        results = [_make_result(severity=Severity.ERROR, message="broken")]
        buf = StringIO()
        format_text(results, tmp_path, buf)
        output = buf.getvalue()
        assert "VC901" in output
        assert "FAIL" in output
        assert "broken" in output

    def test_passed_shown_in_verbose(self, tmp_path: Path):
        results = [_make_result(message="looks good")]
        buf = StringIO()
        format_text(results, tmp_path, buf, verbose=True)
        output = buf.getvalue()
        assert "PASS" in output
        assert "looks good" in output

    def test_default_hides_passed(self, tmp_path: Path):
        """Default mode suppresses passed checks with ERROR severity."""
        results = [_make_result(severity=Severity.INFO, message="ok")]
        buf = StringIO()
        format_text(results, tmp_path, buf)
        output = buf.getvalue()
        # The "ok" message should NOT appear in a result line (score summary is fine)
        lines = [l for l in output.splitlines() if "VC901" in l]
        assert len(lines) == 0

    def test_default_shows_warnings(self, tmp_path: Path):
        """Default mode still shows WARNING checks (they carry advisories)."""
        results = [_make_result(severity=Severity.WARNING, message="advisory note")]
        buf = StringIO()
        format_text(results, tmp_path, buf)
        output = buf.getvalue()
        assert "advisory note" in output
        assert "WARN" in output

    @pytest.mark.parametrize("severity", [Severity.WARNING, Severity.ERROR])
    def test_suggestion_displayed(self, tmp_path: Path, severity: Severity):
        results = [
            _make_result(severity=severity, message="bad", suggestion="do this instead")
        ]
        buf = StringIO()
        format_text(results, tmp_path, buf)
        output = buf.getvalue()
        assert "do this instead" in output
        assert "↳" in output

    def test_score_line(self, tmp_path: Path):
        results = [
            _make_result(message="ok1"),
            _make_result(code="VC902", severity=Severity.ERROR, message="nope"),
        ]
        buf = StringIO()
        format_text(results, tmp_path, buf)
        output = buf.getvalue()
        assert "Score: 1/2" in output
        assert "50%" in output

    def test_abspath_mode(self, tmp_path: Path):
        results = [
            _make_result(
                file_path=Path("src/main.py"),
                severity=Severity.ERROR,
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
            _make_result(message="ok"),
            _make_result(code="VC902", message="fail"),
        ]
        buf = StringIO()
        format_json(results, tmp_path, buf)
        data = json.loads(buf.getvalue())
        assert "connector" in data
        assert "summary" in data
        assert "results" in data

    def test_summary_counts(self, tmp_path: Path):
        results = [
            _make_result(severity=Severity.INFO),
            _make_result(code="VC902", severity=Severity.WARNING),
            _make_result(code="VC903", severity=Severity.ERROR),
        ]
        buf = StringIO()
        format_json(results, tmp_path, buf)
        data = json.loads(buf.getvalue())
        assert data["summary"]["total"] == 3
        assert data["summary"]["failed"] == 1
        assert data["summary"]["errors"] == 1  # VC903 failed with ERROR severity
        assert data["summary"]["warnings"] == 1  # VC902 failed with WARNING severity

    def test_result_fields(self, tmp_path: Path):
        results = [
            _make_result(
                code="VC901",
                name="test-check",
                message="found it",
                severity=Severity.WARNING,
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
        assert r["line"] == 42
        assert r["suggestion"] == "try harder"

    def test_file_path_absolute(self, tmp_path: Path):
        results = [_make_result(file_path=Path("src/main.py"), message="ok")]
        buf = StringIO()
        format_json(results, tmp_path, buf)
        data = json.loads(buf.getvalue())
        fp = data["results"][0]["file_path"]
        assert Path(fp).is_absolute()

    def test_score_pct(self, tmp_path: Path):
        results = [
            _make_result(),
            _make_result(code="VC902"),
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
        results = [_make_result(message="all good")]
        buf = StringIO()
        format_github(results, tmp_path, buf)
        assert buf.getvalue() == ""

    def test_default_line_number(self, tmp_path: Path):
        results = [
            _make_result(
                message="no line",
                severity=Severity.ERROR,
                file_path=Path("src/main.py"),
                line=None,
            )
        ]
        buf = StringIO()
        format_github(results, tmp_path, buf)
        assert "line=1" in buf.getvalue()
