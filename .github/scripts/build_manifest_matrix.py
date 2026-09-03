#!/usr/bin/env python3
"""
Generate the GitHub Actions matrix for config-schema generation
(build-manifest.yml).

Unlike the linter/test matrices, this one is NOT filtered by git changes:
every manager-supported connector's config schema is regenerated on every
run, since the schema feeds the global manifest which must stay complete
and correct even for connectors that weren't touched in the latest push.

Shared git/manifest/output/batching helpers live in _matrix_common.py.
"""

import json

import _matrix_common as common

# ---------------------------------------------------------------------------
# Connector discovery
# ---------------------------------------------------------------------------


def discover_manager_supported_connectors() -> list:
    """Return connector root dirs with manager_supported=true in their manifest.

    Mirrors the eligibility check performed by the `generate_config_schema`
    mise task itself, so the matrix never schedules a job that the task
    would immediately reject.
    """
    return [
        root
        for root in common.discover_connector_roots()
        if common.is_manager_supported(common.load_manifest(root))
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
    connectors = discover_manager_supported_connectors()
    print(f"Manager-supported connectors: {len(connectors)}")

    if not connectors:
        print("No manager-supported connectors, skipping.")
        common.write_output("has_connectors", "false")
        common.write_output(
            "matrix", json.dumps({"include": []}, separators=(",", ":"))
        )
        return

    entries = common.build_batched_matrix(
        connectors, make_entry, type_of=lambda p: p.parts[0]
    )
    print(f"Matrix jobs: {len(entries)}")
    common.write_output("has_connectors", "true")
    common.write_output(
        "matrix", json.dumps({"include": entries}, separators=(",", ":"))
    )


if __name__ == "__main__":
    main()
