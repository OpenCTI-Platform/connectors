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

    # Derive status label from both passed and severity:
    #   PASS  = passed + ERROR/INFO severity (normal pass)
    #   WARN  = WARNING severity (advisory, regardless of passed)
    #   FAIL  = failed + ERROR severity
    #   INFO  = passed + INFO severity … not used yet, kept as PASS
    if result.severity == Severity.WARNING:
        status = _c("WARN", "yellow", stream)
    elif result.severity == Severity.INFO:
        status = _c("PASS", "green", stream)
    else:
        status = _c("FAIL", "red", stream)

    code = _c(result.code, "cyan", stream)
    return f"  {location}: {code} [{status}] {result.message}"


def _write_score(results: list[CheckResult], stream: TextIO) -> None:
    """Write the score summary line."""
    total = len(results)
    if total == 0:
        return

    passed = len([r for r in results if r.severity != Severity.ERROR])
    failed = total - passed
    pct = (passed / total) * 100
    errors = len([r for r in results if r.severity == Severity.ERROR])
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
    verbose: bool = False,
    abspath: bool = False,
) -> None:
    """Format results as human-readable text with colors.

    By default, only failures (FAIL), warnings (WARN), and the score summary
    are displayed.  Use ``verbose=True`` to also show passing checks (PASS).
    """
    failed = [r for r in results if r.severity == Severity.ERROR]
    warnings = [r for r in results if r.severity == Severity.WARNING]
    passed_normal = [r for r in results if r.severity == Severity.INFO]

    def _write_result(result: CheckResult) -> None:
        stream.write(
            f"{_format_result_line(result, connector_path, stream, abspath=abspath)}\n",
        )
        if result.suggestion:
            suggestion = _c(f"    ↳ {result.suggestion}", "dim", stream)
            stream.write(f"{suggestion}\n")

    for result in failed:
        _write_result(result)

    for result in warnings:
        _write_result(result)

    if verbose:
        for result in passed_normal:
            _write_result(result)

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
    passed_count = len([r for r in results if r.severity != Severity.ERROR])

    output = {
        "connector": str(connector_path.resolve()),
        "summary": {
            "total": total,
            "passed": passed_count,
            "failed": total - passed_count,
            "errors": len([r for r in results if r.severity == Severity.ERROR]),
            "warnings": len([r for r in results if r.severity == Severity.WARNING]),
            "score_pct": round((passed_count / total) * 100, 1) if total else 0,
        },
        "results": [
            {
                "code": r.code,
                "name": r.name,
                "message": r.message,
                "severity": r.severity.value,
                "file_path": _abs_path(connector_path, r.file_path),
                "line": r.line,
                "suggestion": r.suggestion,
            }
            for r in output_results
        ],
    }
    json.dump(output, stream, indent=2)
    stream.write("\n")


def format_markdown(
    results: list[CheckResult],
    connector_path: Path,
    stream: TextIO,
    verbose: bool = False,
    abspath: bool = False,
) -> None:
    """Format results as a Markdown document.

    Produces a self-contained Markdown report suitable for pasting into
    Notion, GitHub issues, or any Markdown-capable viewer.
    """
    connector_name = connector_path.resolve().name
    stream.write(f"# Connector Linter Report — `{connector_name}`\n\n")

    total = len(results)
    passed_count = len([r for r in results if r.passed])
    failed_count = total - passed_count
    errors = len([r for r in results if not r.passed and r.severity == Severity.ERROR])
    warnings = len([r for r in results if r.severity == Severity.WARNING])
    pct = (passed_count / total) * 100 if total else 0

    stream.write(f"**Score: {passed_count}/{total} — {pct:.0f}%**\n\n")
    summary_parts = [
        f"{total} checks run",
        f"{passed_count} passed",
        f"{failed_count} failed",
    ]
    if errors:
        summary_parts.append(f"{errors} error(s)")
    if warnings:
        summary_parts.append(f"{warnings} warning(s)")
    stream.write(f"{', '.join(summary_parts)}\n\n")

    failed = [r for r in results if not r.passed]
    warn_results = [r for r in results if r.passed and r.severity == Severity.WARNING]
    passed_normal = [r for r in results if r.passed and r.severity != Severity.WARNING]

    def _md_path(r: CheckResult) -> str:
        if abspath:
            return _abs_path(connector_path, r.file_path)
        return _display_path(connector_path, r.file_path)

    def _md_line(r: CheckResult, icon: str) -> str:
        path = _md_path(r)
        line_part = f":{r.line}" if r.line else ""
        line = f"- {icon} **{r.code}** `{path}{line_part}` — {r.message}"
        if r.suggestion:
            line += f"\n  - 💡 {r.suggestion}"
        return line

    if failed:
        stream.write("## ❌ Failed\n\n")
        for r in failed:
            stream.write(f"{_md_line(r, '❌')}\n")
        stream.write("\n")

    if warn_results:
        stream.write("## ⚠️ Warnings\n\n")
        for r in warn_results:
            stream.write(f"{_md_line(r, '⚠️')}\n")
        stream.write("\n")

    if verbose and passed_normal:
        stream.write("## ✅ Passed\n\n")
        for r in passed_normal:
            stream.write(f"{_md_line(r, '✅')}\n")
        stream.write("\n")


def format_github(
    results: list[CheckResult],
    connector_path: Path,
    stream: TextIO,
) -> None:
    """Format results as GitHub Actions annotations."""
    for result in results:
        if result.severity == Severity.INFO:
            continue
        level = "error" if result.severity == Severity.ERROR else "warning"
        file_path = _repo_relative_path(connector_path, result.file_path)
        line = result.line or 1
        stream.write(
            f"::{level} file={file_path},line={line}::{result.code}: {result.message}\n",
        )
