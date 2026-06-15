#!/usr/bin/env python3
"""
Generate the GitHub Actions build matrix for Alpine connector images.

Scans all connector directories and detects build variants (FIPS) by
inspecting the filesystem — no external config files required.

Outputs one matrix per connector type to $GITHUB_OUTPUT:
  - matrix_external_import, matrix_internal_enrichment, etc.
  - active_types: JSON array of types that have connectors (e.g. '["external_import","stream"]')
  - has_connectors: 'true' or 'false' (global)

Each matrix entry contains:
  - path:           e.g. "external-import/mitre"
  - name:           e.g. "mitre"
  - connector_type: e.g. "external-import"
  - fips:           "true" or "false"
"""

import json
import os
from pathlib import Path

CONNECTOR_TYPE_DIRS = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
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


def write_output(key: str, value: str) -> None:
    """Write a key=value pair to $GITHUB_OUTPUT (or stdout if not set)."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    line = f"{key}={value}\n"
    if output_file:
        with Path(output_file).open("a") as f:
            f.write(line)
    else:
        print(line, end="")


def type_to_output_key(type_dir: str) -> str:
    """Convert type dir name to GHA output key: 'external-import' → 'external_import'."""
    return type_dir.replace("-", "_")


def main() -> None:
    by_type = discover_connectors()
    total = sum(len(v) for v in by_type.values())
    print(f"Discovered {total} connectors with Dockerfiles")

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

    fips_count = sum(
        1 for entries in by_type.values() for e in entries if e["fips"] == "true"
    )
    print(f"  FIPS-enabled connectors: {fips_count}")

    active_types = []
    write_output("has_connectors", "true")

    for type_dir in CONNECTOR_TYPE_DIRS:
        entries = by_type[type_dir]
        key = type_to_output_key(type_dir)
        write_output(
            f"matrix_{key}", json.dumps({"include": entries}, separators=(",", ":"))
        )
        print(f"  {type_dir}: {len(entries)} connectors")
        if entries:
            active_types.append(key)

    write_output("active_types", json.dumps(active_types, separators=(",", ":")))
    print(f"  Active types: {active_types}")


if __name__ == "__main__":
    main()
