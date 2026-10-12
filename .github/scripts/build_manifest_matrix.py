#!/usr/bin/env python3
"""
Generate the GitHub Actions matrix for config-schema generation.

By default (build-manifest.yml) the matrix is NOT filtered by git changes:
every manager-supported connector's config schema is regenerated on every
run, since the schema feeds the global manifest which must stay complete
and correct even for connectors that weren't touched in the latest push.

With CHANGED_ONLY=true (ci-config-schema.yml, on pull requests) it keeps
only the connectors changed since the merge base, so a connector whose
schema cannot be generated is caught before it reaches master. A change to
the schema generation tooling selects every connector.

Shared git/manifest/output/batching helpers live in _matrix_common.py.
"""

import json
import os

import _matrix_common as common

# Changing any of these can break schema generation for every connector.
SCHEMA_TOOLING_PATHS = (
    ".mise/tasks/generate_config_schema.sh",
    ".mise/tasks/_helpers.sh",
    "shared/tools/composer/generate_connectors_config_schemas",
    ".github/scripts/build_manifest_matrix.py",
    ".github/scripts/_matrix_common.py",
    ".github/workflows/ci-config-schema.yml",
)

# ---------------------------------------------------------------------------
# Connector discovery
# ---------------------------------------------------------------------------


def discover_manager_supported_connectors() -> tuple[list, list]:
    """Split manager-supported connectors into (eligible, skipped) roots.

    Eligibility mirrors the checks performed by the `generate_config_schema`
    mise task itself, so the matrix never schedules a job that the task
    would immediately reject: the connector must be manager-supported *and*
    declare pydantic-settings or connectors-sdk.
    """
    eligible: list = []
    skipped: list = []
    for root in common.discover_connector_roots():
        if not common.is_manager_supported(common.load_manifest(root)):
            continue
        target = eligible if common.has_config_schema_deps(root) else skipped
        target.append(root)
    return eligible, skipped


def warn_on_unmaintainable_schemas(skipped: list) -> None:
    """Warn about committed schemas that CI can no longer refresh.

    A connector skipped for missing dependencies but which already has a
    committed config schema is the dangerous case: nothing fails, yet its
    schema silently drifts as the connector's configuration evolves. Warn
    loudly so it gets fixed rather than rotting unnoticed.
    """
    for root in skipped:
        if common.has_config_schema(root):
            common.warn(
                f"{root} is manager_supported and has a committed "
                f"{common.CONFIG_SCHEMA_FILENAME}, but declares neither "
                "pydantic-settings nor connectors-sdk, so generate_config_schema "
                "cannot regenerate it. The committed schema will drift out of "
                "sync until one of these dependencies is declared.",
                file=common.config_schema_path(root),
            )
        else:
            print(f"Skipping {root}: no config-schema dependency declared")


def select_changed(roots: list, base_commit: str | None) -> list:
    """Keep the connector roots changed since *base_commit*.

    Every root is kept when there is no merge base or when the schema
    generation tooling itself changed.
    """
    if base_commit is None or common.has_changes(base_commit, *SCHEMA_TOOLING_PATHS):
        return roots
    return [root for root in roots if common.has_changes(base_commit, str(root))]


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
    connectors, skipped = discover_manager_supported_connectors()
    print(f"Manager-supported connectors: {len(connectors)} ({len(skipped)} skipped)")

    if os.environ.get("CHANGED_ONLY") == "true":
        base_commit = common.get_base_commit()
        connectors = select_changed(connectors, base_commit)
        skipped = select_changed(skipped, base_commit)
        print(f"Connectors selected for this run: {len(connectors)}")

    warn_on_unmaintainable_schemas(skipped)

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
