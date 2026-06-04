"""VC402 — Dockerfile must not use entrypoint.sh.

Modern connectors should use a direct ``ENTRYPOINT`` command::

    ENTRYPOINT ["python", "main.py"]

The legacy ``entrypoint.sh`` wrapper (which just ``cd`` + ``python3 main.py``)
adds unnecessary indirection and an extra file to maintain.

Scope: Common (all connector types).
"""

import re

from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Regex: references to entrypoint.sh anywhere in a Dockerfile line.
#
# Matches any line that mentions "entrypoint.sh" (case-insensitive).
# Used to detect the legacy pattern:
#   COPY entrypoint.sh /
#   ENTRYPOINT ["/entrypoint.sh"]
# ---------------------------------------------------------------------------
_ENTRYPOINT_SH_RE = re.compile(r"entrypoint\.sh", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Regex: direct Python ENTRYPOINT (the preferred modern pattern).
#
# Matches lines like:
#   ENTRYPOINT ["python", "-m", "connector"]
#   ENTRYPOINT ["python3", "main.py"]
#
# The key requirement is the JSON-exec form with "python" as the first
# argument.  This avoids the unnecessary entrypoint.sh wrapper script.
# ---------------------------------------------------------------------------
_ENTRYPOINT_DIRECT_RE = re.compile(r'ENTRYPOINT\s+\[.*"python"', re.IGNORECASE)


@CheckRegistry.register(
    code="VC402",
    name="no-entrypoint-sh",
    description="Dockerfile must not use entrypoint.sh — use direct ENTRYPOINT",
    severity=Severity.ERROR,
)
def check_no_entrypoint_sh(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that Dockerfile does not reference entrypoint.sh."""
    dockerfile_path = ctx.path / "Dockerfile"
    if not dockerfile_path.is_file():
        return [
            CheckFinding(
                message="No Dockerfile found",
                severity=Severity.ERROR,
                suggestion="Add a Dockerfile to the connector.",
            ),
        ]

    with dockerfile_path.open(encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()

    # ---------------------------------------------------------------------------
    # Detection priority:
    #   1. First, scan for entrypoint.sh references (the "bad" pattern).
    #      Commented-out lines (# COPY entrypoint.sh) are skipped — they are
    #      remnants of a migration and not active.
    #   2. If no entrypoint.sh found, check for a direct Python ENTRYPOINT
    #      (the "good" pattern) and report it as passing.
    #   3. Fallback: no entrypoint.sh AND no direct ENTRYPOINT — still PASS
    #      because the absence of entrypoint.sh is the primary goal.
    # ---------------------------------------------------------------------------
    sh_hits: list[tuple[int, str]] = []
    for i, line in enumerate(lines, 1):
        # Skip commented Dockerfile lines — they don't affect the build
        if _ENTRYPOINT_SH_RE.search(line) and not line.lstrip().startswith("#"):
            sh_hits.append((i, line.strip()))

    if sh_hits:
        first = sh_hits[0]
        return [
            CheckFinding(
                message=f"Dockerfile uses entrypoint.sh at line {first[0]}",
                severity=Severity.ERROR,
                file_path=dockerfile_path,
                line=first[0],
                suggestion=(
                    "Remove entrypoint.sh and use "
                    'ENTRYPOINT ["python", "main.py"] '
                    "or similar direct Python invocation."
                ),
            ),
        ]

    # No entrypoint.sh found — check for the preferred direct ENTRYPOINT
    if _ENTRYPOINT_DIRECT_RE.search(content):
        for i, line in enumerate(lines, 1):
            if _ENTRYPOINT_DIRECT_RE.search(line):
                return [
                    CheckFinding(
                        message="Dockerfile uses direct Python ENTRYPOINT ✓",
                        severity=Severity.INFO,
                        file_path=dockerfile_path,
                        line=i,
                    ),
                ]

    # Fallback: no entrypoint.sh reference at all — this is fine.
    # The connector might use CMD or some other mechanism; the key
    # requirement is just the absence of the legacy entrypoint.sh wrapper.
    return [
        CheckFinding(
            message="No entrypoint.sh reference found ✓",
            severity=Severity.INFO,
            file_path=dockerfile_path,
        ),
    ]
