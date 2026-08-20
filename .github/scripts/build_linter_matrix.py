#!/usr/bin/env python3
"""
Generate the GitHub Actions matrix for connector-linter runs.

Scans all connector_manifest.json files and selects connectors that are
either **verified** (verified=true AND last_verified_date is set) or
**manager_supported** (manager_supported=true).

On non-master branches the list is further narrowed to connectors whose
files actually changed, using the same git-diff logic as build_test_matrix.py.

Shared git/manifest/output/batching helpers live in _matrix_common.py.
"""

import json

import _matrix_common as common

# ---------------------------------------------------------------------------
# Manifest scanning
# ---------------------------------------------------------------------------


def discover_eligible_connectors() -> list:
    """Return connector root dirs whose manifest passes eligibility."""
    eligible = []
    for connector_root in common.discover_connector_roots():
        manifest = common.load_manifest(connector_root)
        if common.is_eligible(manifest):
            eligible.append(connector_root)
    return eligible


# ---------------------------------------------------------------------------
# Filtering (change-based, mirrors build_test_matrix.py)
# ---------------------------------------------------------------------------


def should_run(connector_root, base_commit: str | None) -> bool:
    if base_commit is None:
        return True
    return common.has_changes(base_commit, str(connector_root))


# ---------------------------------------------------------------------------
# Matrix building
# ---------------------------------------------------------------------------


def make_entry(connector_roots: list) -> dict:
    names = [
        f"{p.parent.name}/{p.name}" if len(p.parts) >= 2 else str(p)
        for p in connector_roots
    ]
    paths = [str(p) for p in connector_roots]
    # If any connector in the batch is verified-with-date, treat the whole
    # batch as verified: its linter errors must block the PR. Batches only
    # ever contain more than one connector when the eligible count exceeds
    # GITHUB_ACTIONS_JOB_LIMIT, which in practice does not mix verified and
    # manager-supported-only connectors together.
    verified = any(common.is_verified(common.load_manifest(r)) for r in connector_roots)
    return {
        "name": (
            ", ".join(names)
            if len(names) <= 3
            else f"{names[0]} (+{len(names) - 1} more)"
        ),
        "connector_paths": "\n".join(paths),
        "verified": verified,
    }


def main() -> None:
    base_commit = common.get_base_commit()

    eligible = discover_eligible_connectors()
    print(f"Total eligible connectors (verified/manager-supported): {len(eligible)}")

    filtered = [r for r in eligible if should_run(r, base_commit)]
    print(f"Connectors selected for this run: {len(filtered)}")

    if not filtered:
        print("No connectors to lint, skipping.")
        common.write_output("has_connectors", "false")
        common.write_output(
            "matrix", json.dumps({"include": []}, separators=(",", ":"))
        )
        return

    entries = common.build_batched_matrix(
        filtered,
        make_entry,
        type_of=lambda p: (
            f"{p.parts[0] if p.parts else 'unknown'}:"
            f"{'verified' if common.is_verified(common.load_manifest(p)) else 'manager'}"
        ),
    )
    print(f"Matrix jobs: {len(entries)}")
    common.write_output("has_connectors", "true")
    common.write_output(
        "matrix", json.dumps({"include": entries}, separators=(",", ":"))
    )


if __name__ == "__main__":
    main()
