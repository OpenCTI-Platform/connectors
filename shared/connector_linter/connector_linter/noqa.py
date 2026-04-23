"""Inline suppression via ``# noqa`` comments.

Supports the same syntax as flake8:

- ``# noqa`` — suppress all checks on this line
- ``# noqa: VC101`` — suppress only VC101
- ``# noqa: VC101, VC302`` — suppress multiple codes

The noqa directive is matched case-insensitively and can appear anywhere
after a ``#`` on the line.  Works in Python, YAML, Dockerfile, env files,
and any file that uses ``#`` for comments.
"""

import re
from functools import lru_cache
from pathlib import Path

from connector_linter.models import CheckResult

# Matches:
_NOQA_RE = re.compile(
    r"#\s*noqa\b(?:\s*:\s*(?P<codes>[A-Za-z0-9,\s]+))?",
    re.IGNORECASE,
)


def _parse_noqa_codes(match: re.Match) -> set[str] | None:
    """Parse codes from a noqa match.

    Returns ``None`` for a bare ``# noqa`` (suppresses everything),
    or a set of uppercase codes for ``# noqa: VC101, VC302``.
    """
    raw = match.group("codes")
    if raw is None:
        return None  # bare noqa — suppress all
    codes = {c.strip().upper() for c in raw.split(",") if c.strip()}
    return codes or None


@lru_cache(maxsize=256)
def _read_file_lines(file_path: Path) -> tuple[str, ...]:
    """Read and cache file lines (returns tuple for hashability)."""
    try:
        return tuple(file_path.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError):
        return ()


def get_noqa_directives(file_path: Path) -> dict[int, set[str] | None]:
    """Parse all noqa directives from a file.

    Returns a dict mapping line numbers (1-based) to either:
    - ``None`` → bare ``# noqa`` (suppress all codes)
    - ``set[str]`` → specific codes to suppress
    """
    lines = _read_file_lines(file_path)
    directives: dict[int, set[str] | None] = {}

    for i, line in enumerate(lines, 1):
        m = _NOQA_RE.search(line)
        if m:
            directives[i] = _parse_noqa_codes(m)

    return directives


def is_suppressed(result: CheckResult, file_path: Path, line: int) -> bool:
    """Check if a result is suppressed by a noqa directive on its line."""
    directives = get_noqa_directives(file_path)
    directive = directives.get(line)

    if directive is None and line in directives:
        return True  # bare noqa — suppress everything

    return directive is not None and result.code.upper() in directive


def filter_noqa(
    results: list[CheckResult],
    connector_path: Path,
) -> list[CheckResult]:
    """Filter results that are suppressed by noqa directives.

    Only results with both ``file_path`` and ``line`` set are eligible
    for suppression.  Results without location info pass through unchanged.

    *connector_path* is the connector root directory.  When a result carries
    a relative ``file_path`` (common — most checks report paths relative to
    the connector root), it is resolved against *connector_path* so that
    ``_read_file_lines`` opens the correct file on disk.
    """
    _read_file_lines.cache_clear()
    resolved_root = connector_path.resolve()
    filtered: list[CheckResult] = []

    for result in results:
        if result.file_path and result.line:
            # Resolve relative paths against the connector root so
            # _read_file_lines always gets an absolute, unambiguous path.
            abs_path = (
                result.file_path
                if result.file_path.is_absolute()
                else resolved_root / result.file_path
            )
            if is_suppressed(result, abs_path, result.line):
                continue
        filtered.append(result)

    return filtered
