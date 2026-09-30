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

Shared git/output/batching helpers live in _matrix_common.py.
"""

import json
import os
import subprocess
from pathlib import Path

import _matrix_common as common

CONNECTOR_DIRS = ["connectors-sdk"] + common.CONNECTOR_TYPE_DIRS


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


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
    if common.has_changes(base_commit, str(cdir)):
        return True
    if sdk_changed and has_sdk_dependency(cdir):
        return True
    return False


# ---------------------------------------------------------------------------
# Verified status
# ---------------------------------------------------------------------------


def is_verified(req_path: str) -> bool:
    """Check if the connector has "verified": true in its manifest.

    connectors-sdk is always considered verified (it has no manifest).

    Note: unlike _matrix_common.is_verified(), this intentionally does not
    require last_verified_date — kept as-is to preserve this script's
    original (currently unused downstream) "verified" output semantics.
    """
    if connector_type(req_path) == "connectors-sdk":
        return True
    manifest = common.load_manifest(connector_dir(req_path))
    return manifest.get("verified", False) is True


# ---------------------------------------------------------------------------
# Matrix building
# ---------------------------------------------------------------------------


def make_entry(req_paths: list[str]) -> dict:
    names = [connector_name(p) for p in req_paths]
    if len(names) == 1:
        name = f"{connector_type(req_paths[0])}/{names[0]}"
    else:
        name = ", ".join(names)
    verified = any(is_verified(p) for p in req_paths)
    return {
        "name": name,
        "test_requirements": "\n".join(req_paths),
        "verified": verified,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    release_ref = os.environ.get("RELEASE_REF", "master")
    is_master = os.environ.get("GITHUB_REF_NAME") == release_ref
    base_commit = common.get_base_commit()

    changes_outside_scope = False
    sdk_changed = False
    if base_commit and not is_master:
        changes_outside_scope = common.has_changes(
            base_commit,
            *[f":!{d}/**" for d in CONNECTOR_DIRS],
        )
        sdk_changed = common.has_changes(base_commit, "connectors-sdk")

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
        common.write_output("has_tests", "false")
        common.write_output(
            "matrix", json.dumps({"include": []}, separators=(",", ":"))
        )
        return

    entries = common.build_batched_matrix(filtered, make_entry, type_of=connector_type)
    print(f"Matrix jobs: {len(entries)}")
    common.write_output("has_tests", "true")
    common.write_output(
        "matrix", json.dumps({"include": entries}, separators=(",", ":"))
    )


if __name__ == "__main__":
    main()
