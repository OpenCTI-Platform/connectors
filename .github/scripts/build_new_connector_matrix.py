#!/usr/bin/env python3
"""
Generate the GitHub Actions matrix for the "new connector settings" check.

Detects connector directories that are newly added on this branch relative to
the PR base branch (RELEASE_REF) — i.e., directories that do not exist at all
at the merge-base commit. These are connectors introduced for the first time
in this PR, as opposed to existing connectors receiving further changes.

Newly-added connectors must implement configuration via connectors-sdk's
BaseConnectorSettings (or, at minimum, pydantic_settings.BaseSettings) instead
of the legacy get_config_variable() pattern. This is enforced by running
`connector-linter check --select VC305` against them as a blocking check,
independent of build_linter_matrix.py's eligibility rules (which only cover
already verified/manager-supported connectors and never block a PR).

Shared git/output/batching helpers live in _matrix_common.py.
"""

import json

import _matrix_common as common

# ---------------------------------------------------------------------------
# Connector discovery
# ---------------------------------------------------------------------------


def discover_new_connectors(base_commit: str | None) -> list:
    """Return connector roots that did not exist at *base_commit* at all.

    If the base commit can't be resolved, we conservatively report no new
    connectors rather than flagging every pre-existing connector as "new".
    """
    if base_commit is None:
        return []
    return [
        root
        for root in common.discover_connector_roots()
        if not common.existed_at_commit(base_commit, root)
    ]


# ---------------------------------------------------------------------------
# Matrix building
# ---------------------------------------------------------------------------


def make_entry(connector_roots: list) -> dict:
    names = [f"{p.parent.name}/{p.name}" for p in connector_roots]
    paths = [str(p) for p in connector_roots]
    return {
        "name": (
            ", ".join(names)
            if len(names) <= 3
            else f"{names[0]} (+{len(names) - 1} more)"
        ),
        "connector_paths": "\n".join(paths),
    }


def main() -> None:
    base_commit = common.get_base_commit()
    new_connectors = discover_new_connectors(base_commit)

    print(f"Base commit: {base_commit or 'unknown'}")
    print(f"Newly added connector directories: {len(new_connectors)}")
    for root in new_connectors:
        print(f"  - {root}")

    if not new_connectors:
        print("No newly added connectors, skipping.")
        common.write_output("has_connectors", "false")
        common.write_output(
            "matrix", json.dumps({"include": []}, separators=(",", ":"))
        )
        return

    entries = common.build_batched_matrix(
        new_connectors, make_entry, type_of=lambda p: p.parts[0]
    )
    print(f"Matrix jobs: {len(entries)}")
    common.write_output("has_connectors", "true")
    common.write_output(
        "matrix", json.dumps({"include": entries}, separators=(",", ":"))
    )


if __name__ == "__main__":
    main()
