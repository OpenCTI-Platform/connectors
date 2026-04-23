"""Tests for noqa.py: parsing directives and suppression logic."""

from pathlib import Path

from connector_linter.models import CheckResult, Severity
from connector_linter.noqa import (
    _NOQA_RE,
    _parse_noqa_codes,
    filter_noqa,
    get_noqa_directives,
    is_suppressed,
)


def _result(
    code: str = "VC101",
    file_path: Path | None = None,
    line: int | None = None,
    passed: bool = False,
) -> CheckResult:
    return CheckResult(
        code=code,
        name="test",
        message="test",
        severity=Severity.ERROR,
        passed=passed,
        file_path=file_path,
        line=line,
    )


class TestNoqaRegex:
    """_NOQA_RE matches the expected patterns."""

    def test_bare_noqa(self):
        assert _NOQA_RE.search("x = 1  # noqa")

    def test_noqa_with_code(self):
        m = _NOQA_RE.search("x = 1  # noqa: VC101")
        assert m
        assert m.group("codes").strip() == "VC101"

    def test_noqa_multiple_codes(self):
        m = _NOQA_RE.search("x = 1  # noqa: VC101, VC302")
        assert m
        assert "VC101" in m.group("codes")
        assert "VC302" in m.group("codes")

    def test_case_insensitive(self):
        assert _NOQA_RE.search("x = 1  # NOQA")
        assert _NOQA_RE.search("x = 1  # Noqa: VC101")

    def test_no_match(self):
        assert not _NOQA_RE.search("x = 1  # normal comment")


class TestParseNoqaCodes:
    def test_bare_returns_none(self):
        m = _NOQA_RE.search("# noqa")
        assert _parse_noqa_codes(m) is None

    def test_single_code(self):
        m = _NOQA_RE.search("# noqa: VC101")
        codes = _parse_noqa_codes(m)
        assert codes == {"VC101"}

    def test_multiple_codes(self):
        m = _NOQA_RE.search("# noqa: VC101, VC302, vc501")
        codes = _parse_noqa_codes(m)
        assert codes == {"VC101", "VC302", "VC501"}  # uppercased


class TestGetNoqaDirectives:
    def test_parse_file(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("line1\nline2  # noqa\nline3  # noqa: VC101\n")
        directives = get_noqa_directives(f)
        assert 1 not in directives
        assert directives[2] is None  # bare noqa
        assert directives[3] == {"VC101"}


class TestIsSuppressed:
    def test_bare_noqa_suppresses(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("x = 1  # noqa\n")
        r = _result(code="VC999", file_path=f, line=1)
        assert is_suppressed(r, f, 1)

    def test_matching_code_suppresses(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("x = 1  # noqa: VC101\n")
        r = _result(code="VC101", file_path=f, line=1)
        assert is_suppressed(r, f, 1)

    def test_wrong_code_no_suppress(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("x = 1  # noqa: VC999\n")
        r = _result(code="VC101", file_path=f, line=1)
        assert not is_suppressed(r, f, 1)

    def test_no_directive_no_suppress(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        r = _result(code="VC101", file_path=f, line=1)
        assert not is_suppressed(r, f, 1)


class TestFilterNoqa:
    def test_suppresses_matching(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("x = 1  # noqa: VC101\n")
        results = [_result(code="VC101", file_path=f, line=1)]
        filtered = filter_noqa(results, tmp_path)
        assert len(filtered) == 0

    def test_keeps_non_matching(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("x = 1  # noqa: VC999\n")
        results = [_result(code="VC101", file_path=f, line=1)]
        filtered = filter_noqa(results, tmp_path)
        assert len(filtered) == 1

    def test_no_location_passes_through(self, tmp_path: Path):
        results = [_result(code="VC101", file_path=None, line=None)]
        filtered = filter_noqa(results, tmp_path)
        assert len(filtered) == 1

    def test_mixed(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text("line1  # noqa: VC101\nline2\n")
        results = [
            _result(code="VC101", file_path=f, line=1),  # suppressed
            _result(code="VC101", file_path=f, line=2),  # kept
            _result(code="VC102", file_path=None, line=None),  # kept (no location)
        ]
        filtered = filter_noqa(results, tmp_path)
        assert len(filtered) == 2

    def test_relative_path_resolved(self, tmp_path: Path):
        """Relative file_path is resolved against connector_path."""
        sub = tmp_path / "src"
        sub.mkdir()
        f = sub / "main.py"
        f.write_text("x = 1  # noqa: VC101\n")
        # Check reports a relative path (common for checks)
        results = [_result(code="VC101", file_path=Path("src/main.py"), line=1)]
        filtered = filter_noqa(results, tmp_path)
        assert len(filtered) == 0
