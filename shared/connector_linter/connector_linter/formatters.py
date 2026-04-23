"""Output formatters for check results."""

import json
from pathlib import Path
from typing import TextIO

from connector_linter.models import CheckResult, Severity

# ANSI color codes
_COLORS = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _use_color(stream: TextIO) -> bool:
    """Determine if we should use ANSI colors on this stream."""
    return hasattr(stream, "isatty") and stream.isatty()


def _c(text: str, color: str, stream: TextIO) -> str:
    """Colorize text if the stream supports it."""
    if not _use_color(stream):
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def _repo_relative_path(connector_path: Path, file_path: Path | None) -> str:
    """Resolve a file_path to be relative to the git repository root.

    GitHub Actions ``::error file=`` requires paths relative to the repo root.
    Falls back to absolute if not inside a git repository.
    """
    base = connector_path.resolve()
    full = base / file_path if file_path else base

    # Walk up to find .git directory
    candidate = full if full.is_dir() else full.parent
    while candidate != candidate.parent:
        if (candidate / ".git").exists():
            try:
                return str(full.relative_to(candidate))
            except ValueError:
                break
        candidate = candidate.parent

    return str(full)


def _abs_path(connector_path: Path, file_path: Path | None) -> str:
    """Resolve a relative file_path to absolute based on the connector root."""
    base = connector_path.resolve()
    if file_path:
        return str(base / file_path)
    return str(base)


def _display_path(connector_path: Path, file_path: Path | None) -> str:
    """Build a display path preserving the CLI-provided connector path.

    If *file_path* is absolute (as produced by most checks), strip the
    resolved connector root so the result stays relative to the CLI argument.
    """
    if not file_path:
        return str(connector_path)

    if file_path.is_absolute():
        try:
            rel = file_path.relative_to(connector_path.resolve())
            return str(connector_path / rel)
        except ValueError:
            return str(file_path)
    return str(connector_path / file_path)


def _format_result_line(
    result: CheckResult,
    connector_path: Path,
    stream: TextIO,
    abspath: bool = False,
) -> str:
    """Format a single result as a colored line."""
    if abspath:
        display = _abs_path(connector_path, result.file_path)
    else:
        display = _display_path(connector_path, result.file_path)
    line_part = f":{result.line}" if result.line else ""
    location = f"{display}{line_part}"

    # Derive status from passed first, then use severity for non-passing advisories.
    # PASS = check passed (any severity), FAIL = failed error, WARN = failed advisory.
    if result.passed:
        status = _c("PASS", "green", stream)
    elif result.severity in (Severity.WARNING, Severity.INFO):
        status = _c("WARN", "yellow", stream)
    else:
        status = _c("FAIL", "red", stream)

    code = _c(result.code, "cyan", stream)
    return f"  {location}: {code} [{status}] {result.message}"


def _write_score(results: list[CheckResult], stream: TextIO) -> None:
    """Write the score summary line."""
    total = len(results)
    if total == 0:
        return

    passed = len([r for r in results if r.passed])
    failed = total - passed
    pct = (passed / total) * 100
    errors = len([r for r in results if not r.passed and r.severity == Severity.ERROR])
    warnings = len([r for r in results if r.severity == Severity.WARNING])

    stream.write(f"  {'─' * 60}\n")

    if pct == 100:
        score_str = _c(f"Score: {passed}/{total} — {pct:.0f}%", "green", stream)
    elif pct >= 50:
        score_str = _c(f"Score: {passed}/{total} — {pct:.0f}%", "yellow", stream)
    else:
        score_str = _c(f"Score: {passed}/{total} — {pct:.0f}%", "red", stream)

    stream.write(f"  {score_str}\n")

    detail_parts = [f"{total} checks run", f"{passed} passed", f"{failed} failed"]
    if errors:
        detail_parts.append(f"{errors} error(s)")
    if warnings:
        detail_parts.append(f"{warnings} warning(s)")
    stream.write(f"  {', '.join(detail_parts)}\n")

    if failed == 0:
        stream.write(f"  {_c('✅ Connector is compliant!', 'green', stream)}\n")
    else:
        stream.write(f"  {_c('❌ Connector has issues to fix.', 'red', stream)}\n")


def format_text(
    results: list[CheckResult],
    connector_path: Path,
    stream: TextIO,
    quiet: bool = False,
    abspath: bool = False,
) -> None:
    """Format results as human-readable text with colors."""
    failed = [r for r in results if not r.passed]
    passed = [r for r in results if r.passed]

    for result in failed:
        stream.write(
            f"{_format_result_line(result, connector_path, stream, abspath=abspath)}\n",
        )
        if result.suggestion:
            suggestion = _c(f"    ↳ {result.suggestion}", "dim", stream)
            stream.write(f"{suggestion}\n")

    if not quiet:
        for result in passed:
            stream.write(
                f"{_format_result_line(result, connector_path, stream, abspath=abspath)}\n",
            )
    else:
        # In quiet mode, still show passed warnings/info (they carry advisories)
        for result in passed:
            if result.severity in (Severity.WARNING, Severity.INFO):
                stream.write(
                    f"{_format_result_line(result, connector_path, stream, abspath=abspath)}\n",
                )

    stream.write("\n")
    _write_score(results, stream)


def format_json(
    results: list[CheckResult],
    connector_path: Path,
    stream: TextIO,
) -> None:
    """Format results as JSON."""
    output_results = results
    total = len(results)
    passed_count = len([r for r in results if r.passed])

    output = {
        "connector": str(connector_path.resolve()),
        "summary": {
            "total": total,
            "passed": passed_count,
            "failed": total - passed_count,
            "errors": len(
                [r for r in results if not r.passed and r.severity == Severity.ERROR]
            ),
            "warnings": len([r for r in results if r.severity == Severity.WARNING]),
            "score_pct": round((passed_count / total) * 100, 1) if total else 0,
        },
        "results": [
            {
                "code": r.code,
                "name": r.name,
                "message": r.message,
                "severity": r.severity.value,
                "passed": r.passed,
                "file_path": _abs_path(connector_path, r.file_path),
                "line": r.line,
                "suggestion": r.suggestion,
            }
            for r in output_results
        ],
    }
    json.dump(output, stream, indent=2)
    stream.write("\n")


def format_github(
    results: list[CheckResult],
    connector_path: Path,
    stream: TextIO,
) -> None:
    """Format results as GitHub Actions annotations."""
    for result in results:
        if result.passed:
            continue
        level = "error" if result.severity == Severity.ERROR else "warning"
        file_path = _repo_relative_path(connector_path, result.file_path)
        line = result.line or 1
        stream.write(
            f"::{level} file={file_path},line={line}::{result.code}: {result.message}\n",
        )
