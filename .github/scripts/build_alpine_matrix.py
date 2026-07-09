#!/usr/bin/env python3
"""
Generate the GitHub Actions build matrix for Alpine connector images.

Scans all connector directories and detects build variants (FIPS) by
inspecting the filesystem — no external config files required.

When BUILD_MODE is "rolling" or "prerelease", only connectors with changes
since the previous commit are included (unless shared dependencies changed,
in which case all connectors are rebuilt). On "release" (tags), all connectors
are always built.

Outputs one matrix per connector type to $GITHUB_OUTPUT:
  - matrix_external_import, matrix_internal_enrichment, etc.
  - active_types: JSON array of types that have connectors
  - has_connectors: 'true' or 'false' (global)

Each matrix entry contains:
  - path:           e.g. "external-import/mitre"
  - name:           e.g. "mitre"
  - connector_type: e.g. "external-import"
  - fips:           "true" or "false"
"""

import json
import os
import subprocess
from pathlib import Path

import _matrix_common as common

CONNECTOR_TYPE_DIRS = common.CONNECTOR_TYPE_DIRS

# Paths that, if changed, trigger a full rebuild of all connectors
SHARED_PATHS = [
    "connectors-sdk/",
    "shared/",
    ".github/actions/build-connector-image/",
    ".github/workflows/build-all-connectors.yml",
    ".github/workflows/build-alpine.yml",
    ".github/workflows/build-connector-type.yml",
    ".github/scripts/build_alpine_matrix.py",
    "Dockerfile_ubi9",
]


def discover_connectors() -> dict[str, list[dict]]:
    """Discover all connector directories, grouped by type.

    Build variants are detected from the filesystem:
      - FIPS: presence of Dockerfile_fips alongside Dockerfile
    """
    by_type: dict[str, list[dict]] = {t: [] for t in CONNECTOR_TYPE_DIRS}

    for type_dir in CONNECTOR_TYPE_DIRS:
        type_path = Path(type_dir)
        if not type_path.is_dir():
            continue

        for connector_path in sorted(type_path.iterdir()):
            if not connector_path.is_dir():
                continue
            if connector_path.name.startswith((".", "_")):
                continue
            if not (connector_path / "Dockerfile").exists():
                print(f"⚠️  Skipping {connector_path} — no Dockerfile")
                continue

            fips = "true" if (connector_path / "Dockerfile_fips").exists() else "false"

            by_type[type_dir].append(
                {
                    "path": str(connector_path),
                    "name": connector_path.name,
                    "connector_type": type_dir,
                    "fips": fips,
                }
            )

    return by_type


def get_changed_files() -> set[str]:
    """Get files changed between HEAD~1 and HEAD."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return set(result.stdout.strip().splitlines())
    except subprocess.CalledProcessError:
        print("⚠️  git diff failed — rebuilding all connectors")
        return set()


def should_build_all(changed_files: set[str]) -> bool:
    """Check if shared dependencies changed, requiring a full rebuild."""
    for changed in changed_files:
        for shared_path in SHARED_PATHS:
            if changed.startswith(shared_path):
                print(f"  🔄 Shared path changed: {changed} → full rebuild")
                return True
    return False


def get_changed_connectors(changed_files: set[str]) -> set[str]:
    """Extract connector paths (e.g. 'external-import/mitre') from changed files."""
    connector_paths = set()
    for changed in changed_files:
        parts = changed.split("/")
        if len(parts) >= 2 and parts[0] in CONNECTOR_TYPE_DIRS:
            connector_paths.add(f"{parts[0]}/{parts[1]}")
    return connector_paths


def filter_changed(
    by_type: dict[str, list[dict]], build_mode: str
) -> dict[str, list[dict]]:
    """Filter connectors to only those with changes (non-release modes)."""
    if build_mode == "release":
        print("  📦 Release mode — building all connectors")
        return by_type

    changed_files = get_changed_files()
    if not changed_files:
        print("  ⚠️  No changed files detected — building all connectors")
        return by_type

    if should_build_all(changed_files):
        return by_type

    changed_connectors = get_changed_connectors(changed_files)
    if not changed_connectors:
        print("  ✅ No connector changes detected — nothing to build")
        return {t: [] for t in CONNECTOR_TYPE_DIRS}

    print(f"  📋 Changed connectors: {sorted(changed_connectors)}")

    filtered: dict[str, list[dict]] = {t: [] for t in CONNECTOR_TYPE_DIRS}
    for type_dir in CONNECTOR_TYPE_DIRS:
        for entry in by_type[type_dir]:
            if entry["path"] in changed_connectors:
                filtered[type_dir].append(entry)

    return filtered


write_output = common.write_output


def type_to_output_key(type_dir: str) -> str:
    """Convert type dir name to GHA output key: 'external-import' → 'external_import'."""
    return type_dir.replace("-", "_")


def main() -> None:
    build_mode = os.environ.get("BUILD_MODE", "release")
    by_type = discover_connectors()
    total = sum(len(v) for v in by_type.values())
    print(f"Discovered {total} connectors with Dockerfiles (mode: {build_mode})")

    if total == 0:
        print("No connectors found.")
        write_output("has_connectors", "false")
        write_output("active_types", "[]")
        for type_dir in CONNECTOR_TYPE_DIRS:
            key = type_to_output_key(type_dir)
            write_output(
                f"matrix_{key}", json.dumps({"include": []}, separators=(",", ":"))
            )
        return

    # Filter to changed connectors only (non-release modes)
    by_type = filter_changed(by_type, build_mode)
    build_count = sum(len(v) for v in by_type.values())

    if build_count == 0:
        print("No connectors to build.")
        write_output("has_connectors", "false")
        write_output("active_types", "[]")
        for type_dir in CONNECTOR_TYPE_DIRS:
            key = type_to_output_key(type_dir)
            write_output(
                f"matrix_{key}", json.dumps({"include": []}, separators=(",", ":"))
            )
        return

    fips_count = sum(
        1 for entries in by_type.values() for e in entries if e["fips"] == "true"
    )
    print(f"  Building {build_count}/{total} connectors (FIPS: {fips_count})")

    active_types = []
    write_output("has_connectors", "true")

    for type_dir in CONNECTOR_TYPE_DIRS:
        entries = by_type[type_dir]
        key = type_to_output_key(type_dir)
        write_output(
            f"matrix_{key}", json.dumps({"include": entries}, separators=(",", ":"))
        )
        if entries:
            print(f"  {type_dir}: {len(entries)} connectors")
            active_types.append(key)

    write_output("active_types", json.dumps(active_types, separators=(",", ":")))
    print(f"  Active types: {active_types}")


if __name__ == "__main__":
    main()
