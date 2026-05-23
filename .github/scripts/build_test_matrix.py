#!/usr/bin/env python3
"""
Generate the GitHub Actions test matrix for connector tests.

Applies the same filtering logic as run_test.sh to decide which connectors
need testing, then builds a matrix respecting the GitHub Actions job limit.

Filtering rules (mirrors run_test.sh):
  1. On master branch              → include all connectors
  2. Changes outside connector dirs → include all connectors
  3. connectors-sdk changed + connector depends on it → include that connector
  4. Connector itself changed       → include that connector
  5. Otherwise                      → skip

Batching rules:
  - Below 256 jobs → one job per connector (maximum granularity)
  - At or above 256 jobs → batch by connector type to stay under the limit
"""

import json
import math
import os
import subprocess
from pathlib import Path

GITHUB_ACTIONS_JOB_LIMIT = 256

CONNECTOR_DIRS = [
    "connectors-sdk",
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]


# ---------------------------------------------------------------------------
# Git helpers
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


def has_sdk_dependency(connector_dir: Path) -> bool:
    result = subprocess.run(
        ["grep", "-rl", "connectors-sdk", str(connector_dir)],
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


# ---------------------------------------------------------------------------
# Per-connector helpers
# ---------------------------------------------------------------------------


def connector_dir(req_path: str) -> Path:
    """
    Directory that owns the connector — mirrors `$project/..` from run_test.sh,
    where $project is dirname(req_path).

    Examples:
      external-import/my-connector/tests/test-requirements.txt → external-import/my-connector
      connectors-sdk/tests/test-requirements.txt               → connectors-sdk
      stream/sekoia-intel/src/test-requirements.txt            → stream/sekoia-intel
    """
    return Path(req_path).parent.parent


def connector_type(req_path: str) -> str:
    """Top-level directory, e.g. 'external-import'."""
    return Path(req_path).parts[0]


def connector_name(req_path: str) -> str:
    """Second path segment, e.g. 'my-connector'."""
    parts = Path(req_path).parts
    return parts[1] if len(parts) >= 2 else req_path


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def should_run(
    req_path: str,
    base_commit: str | None,
    is_master: bool,
    changes_outside_scope: bool,
    sdk_changed: bool,
) -> bool:
    if is_master or changes_outside_scope:
        return True
    if base_commit is None:
        return True  # no git history, run everything

    cdir = connector_dir(req_path)
    if has_changes(base_commit, str(cdir)):
        return True
    if sdk_changed and has_sdk_dependency(cdir):
        return True
    return False


# ---------------------------------------------------------------------------
# Matrix building
# ---------------------------------------------------------------------------


def make_entry(req_paths: list[str]) -> dict:
    names = [connector_name(p) for p in req_paths]
    if len(names) == 1:
        name = f"{connector_type(req_paths[0])}/{names[0]}"
    else:
        name = ", ".join(names)
    return {"name": name, "test_requirements": "\n".join(req_paths)}


def build_matrix(paths: list[str]) -> list[dict]:
    if len(paths) <= GITHUB_ACTIONS_JOB_LIMIT:
        return [make_entry([p]) for p in paths]

    # Batch by connector type to stay under the job limit
    groups: dict[str, list[str]] = {}
    for p in paths:
        groups.setdefault(connector_type(p), []).append(p)

    batch_size = math.ceil(len(paths) / GITHUB_ACTIONS_JOB_LIMIT)
    entries = []
    for _, cpaths in sorted(groups.items()):
        for i in range(0, len(cpaths), batch_size):
            entries.append(make_entry(cpaths[i : i + batch_size]))
    return entries


# ---------------------------------------------------------------------------
# Entry point
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


def main() -> None:
    release_ref = os.environ.get("RELEASE_REF", "master")
    is_master = os.environ.get("GITHUB_REF_NAME") == release_ref
    base_commit = get_base_commit()

    changes_outside_scope = False
    sdk_changed = False
    if base_commit and not is_master:
        changes_outside_scope = has_changes(
            base_commit,
            *[f":!{d}/**" for d in CONNECTOR_DIRS],
        )
        sdk_changed = has_changes(base_commit, "connectors-sdk")

    all_paths = [
        str(Path(p))
        for p in subprocess.run(
            ["find", ".", "-name", "test-requirements.txt", "-type", "f"],
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        if p.strip()
    ]
    all_paths.sort()

    filtered = [
        p
        for p in all_paths
        if should_run(p, base_commit, is_master, changes_outside_scope, sdk_changed)
    ]

    print(f"Total connectors with tests: {len(all_paths)}")
    print(f"Connectors selected for this run: {len(filtered)}")

    if not filtered:
        print("No connectors to test, skipping.")
        write_output("has_tests", "false")
        write_output("matrix", json.dumps({"include": []}, separators=(",", ":")))
        return

    entries = build_matrix(filtered)
    print(f"Matrix jobs: {len(entries)}")
    write_output("has_tests", "true")
    write_output("matrix", json.dumps({"include": entries}, separators=(",", ":")))


if __name__ == "__main__":
    main()
