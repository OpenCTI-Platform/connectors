#!/usr/bin/env python3
"""
Generate the GitHub Actions matrix for connector-linter runs.

Scans all connector_manifest.json files and selects connectors that are
either **verified** (verified=true AND last_verified_date is set) or
**manager_supported** (manager_supported=true).

On non-master branches the list is further narrowed to connectors whose
files actually changed, using the same git-diff logic as build_test_matrix.py.
"""

import json
import math
import os
import subprocess
from pathlib import Path

GITHUB_ACTIONS_JOB_LIMIT = 256

CONNECTOR_DIRS = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]


# ---------------------------------------------------------------------------
# Git helpers (same as build_test_matrix.py)
# ---------------------------------------------------------------------------


def git(*args: str) -> str:
    return subprocess.run(
        ["git"] + list(args), capture_output=True, text=True
    ).stdout.strip()


def get_base_commit() -> str | None:
    release_ref = os.environ.get("RELEASE_REF", "master")
    commit = git("merge-base", f"origin/{release_ref}", "HEAD")
    return commit or None


def has_changes(base_commit: str, *pathspecs: str) -> bool:
    result = subprocess.run(
        ["git", "diff", "--name-only", base_commit, "HEAD", "--"] + list(pathspecs),
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


# ---------------------------------------------------------------------------
# Manifest scanning
# ---------------------------------------------------------------------------


def is_eligible(manifest: dict) -> bool:
    """Return True if connector is verified-with-date or manager-supported."""
    verified = manifest.get("verified", False) is True
    has_date = manifest.get("last_verified_date") not in (None, "", False)
    manager = manifest.get("manager_supported", False) is True
    return (verified and has_date) or manager


def discover_eligible_connectors() -> list[Path]:
    """Return connector root dirs whose manifest passes eligibility."""
    eligible: list[Path] = []
    for ctype in CONNECTOR_DIRS:
        ctype_dir = Path(ctype)
        if not ctype_dir.is_dir():
            continue
        for manifest_path in sorted(
            ctype_dir.rglob("__metadata__/connector_manifest.json")
        ):
            try:
                manifest = json.loads(manifest_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            if is_eligible(manifest):
                # connector root is two levels up from __metadata__/connector_manifest.json
                eligible.append(manifest_path.parent.parent)
    return eligible


# ---------------------------------------------------------------------------
# Filtering (change-based, mirrors build_test_matrix.py)
# ---------------------------------------------------------------------------


def should_run(
    connector_root: Path,
    base_commit: str | None,
) -> bool:
    if base_commit is None:
        return True

    if has_changes(base_commit, str(connector_root)):
        return True
    return False


# ---------------------------------------------------------------------------
# Matrix building
# ---------------------------------------------------------------------------


def make_entry(connector_roots: list[Path]) -> dict:
    names = [
        f"{p.parent.name}/{p.name}" if len(p.parts) >= 2 else str(p)
        for p in connector_roots
    ]
    paths = [str(p) for p in connector_roots]
    return {
        "name": (
            ", ".join(names)
            if len(names) <= 3
            else f"{names[0]} (+{len(names) - 1} more)"
        ),
        "connector_paths": "\n".join(paths),
    }


def build_matrix(roots: list[Path]) -> list[dict]:
    if len(roots) <= GITHUB_ACTIONS_JOB_LIMIT:
        return [make_entry([r]) for r in roots]

    # Batch by connector type to stay under the limit
    groups: dict[str, list[Path]] = {}
    for r in roots:
        ctype = r.parts[0] if r.parts else "unknown"
        groups.setdefault(ctype, []).append(r)

    batch_size = math.ceil(len(roots) / GITHUB_ACTIONS_JOB_LIMIT)
    entries = []
    for _, cpaths in sorted(groups.items()):
        for i in range(0, len(cpaths), batch_size):
            entries.append(make_entry(cpaths[i : i + batch_size]))
    return entries


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def write_output(key: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    line = f"{key}={value}\n"
    if output_file:
        with Path(output_file).open("a") as f:
            f.write(line)
    else:
        print(line, end="")


def main() -> None:
    base_commit = get_base_commit()

    eligible = discover_eligible_connectors()
    print(f"Total eligible connectors (verified/manager-supported): {len(eligible)}")

    filtered = [r for r in eligible if should_run(r, base_commit)]
    print(f"Connectors selected for this run: {len(filtered)}")

    if not filtered:
        print("No connectors to lint, skipping.")
        write_output("has_connectors", "false")
        write_output("matrix", json.dumps({"include": []}, separators=(",", ":")))
        return

    entries = build_matrix(filtered)
    print(f"Matrix jobs: {len(entries)}")
    write_output("has_connectors", "true")
    write_output("matrix", json.dumps({"include": entries}, separators=(",", ":")))


if __name__ == "__main__":
    main()
