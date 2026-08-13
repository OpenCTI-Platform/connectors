#!/usr/bin/env python3
"""
Shared helpers for the GitHub Actions matrix-generation scripts.

Centralizes logic that was duplicated across build_linter_matrix.py,
build_new_connector_matrix.py, build_test_matrix.py and
build_alpine_matrix.py: git helpers, connector manifest eligibility rules,
$GITHUB_OUTPUT writing, and matrix batching (to stay under the GitHub
Actions 256-job-per-matrix limit).

Not a CI entry point itself — each build_*_matrix.py script keeps its own
`main()` and script-specific discovery/filtering rules, and imports from
here (this file lives alongside them, so a plain `import _matrix_common`
resolves without any packaging).
"""

import json
import math
import os
import subprocess
from pathlib import Path
from typing import Any, Callable, TypeVar

GITHUB_ACTIONS_JOB_LIMIT = 256

# Top-level connector-type directories, shared by every script that walks
# the repo looking for connectors.
CONNECTOR_TYPE_DIRS = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def git(*args: str) -> str:
    return subprocess.run(
        ["git"] + list(args), capture_output=True, text=True
    ).stdout.strip()


def get_base_commit() -> str | None:
    """Merge-base commit between origin/$RELEASE_REF and HEAD (default: master)."""
    release_ref = os.environ.get("RELEASE_REF", "master")
    commit = git("merge-base", f"origin/{release_ref}", "HEAD")
    return commit or None


def has_changes(base_commit: str, *pathspecs: str) -> bool:
    """True if any file under *pathspecs* changed between base_commit and HEAD."""
    result = subprocess.run(
        ["git", "diff", "--name-only", base_commit, "HEAD", "--"] + list(pathspecs),
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def existed_at_commit(commit: str, path: Path) -> bool:
    """True if *path* already existed (as a blob/tree) at *commit*."""
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}:{path.as_posix()}"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Connector manifest helpers
# ---------------------------------------------------------------------------


def load_manifest(connector_root: Path) -> dict[str, Any]:
    """Load __metadata__/connector_manifest.json, or {} if missing/invalid."""
    manifest_path = connector_root / "__metadata__" / "connector_manifest.json"
    if not manifest_path.exists():
        return {}
    try:
        return json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def is_verified(manifest: dict[str, Any]) -> bool:
    """True if verified=true AND last_verified_date is set."""
    verified = manifest.get("verified", False) is True
    has_date = manifest.get("last_verified_date") not in (None, "", False)
    return verified and has_date


def is_manager_supported(manifest: dict[str, Any]) -> bool:
    return manifest.get("manager_supported", False) is True


def is_eligible(manifest: dict[str, Any]) -> bool:
    """True if verified-with-date or manager-supported."""
    return is_verified(manifest) or is_manager_supported(manifest)


# ---------------------------------------------------------------------------
# Connector discovery
# ---------------------------------------------------------------------------

_CONNECTOR_ROOT_MARKERS = ("src", "__metadata__", "Dockerfile", "docker-compose.yml")


def is_connector_root(path: Path) -> bool:
    """True if *path* looks like a connector root directory."""
    return any((path / marker).exists() for marker in _CONNECTOR_ROOT_MARKERS)


def discover_connector_roots(
    connector_dirs: list[str] = CONNECTOR_TYPE_DIRS,
) -> list[Path]:
    """All connector root dirs currently on the filesystem, under *connector_dirs*."""
    roots: list[Path] = []
    for ctype in connector_dirs:
        ctype_dir = Path(ctype)
        if not ctype_dir.is_dir():
            continue
        for entry in sorted(ctype_dir.iterdir()):
            if (
                entry.is_dir()
                and not entry.name.startswith(".")
                and is_connector_root(entry)
            ):
                roots.append(entry)
    return roots


# ---------------------------------------------------------------------------
# Matrix batching
# ---------------------------------------------------------------------------


def build_batched_matrix(
    items: list[T],
    make_entry: Callable[[list[T]], dict],
    type_of: Callable[[T], str],
    limit: int = GITHUB_ACTIONS_JOB_LIMIT,
) -> list[dict]:
    """Build GitHub Actions matrix entries, batching by type if over *limit*.

    Below the limit, each item gets its own matrix entry (maximum
    granularity/parallelism). At or above the limit, items are grouped by
    ``type_of(item)`` and packed into batches to stay under the GitHub
    Actions per-matrix job cap.
    """
    if len(items) <= limit:
        return [make_entry([item]) for item in items]

    groups: dict[str, list[T]] = {}
    for item in items:
        groups.setdefault(type_of(item), []).append(item)

    batch_size = math.ceil(len(items) / limit)
    entries = []
    for _, group_items in sorted(groups.items()):
        for i in range(0, len(group_items), batch_size):
            entries.append(make_entry(group_items[i : i + batch_size]))
    return entries


# ---------------------------------------------------------------------------
# GitHub Actions output
# ---------------------------------------------------------------------------


def write_output(key: str, value: str) -> None:
    """Write a key=value pair to $GITHUB_OUTPUT (or stdout if not set)."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    line = f"{key}={value}\n"
    if output_file:
        with Path(output_file).open("a") as f:
            f.write(line)
    else:
        print(line, end="")
