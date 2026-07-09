#!/usr/bin/env python3
"""Check connector identity uniqueness constraints used by CI image naming.

This validates:
- manifest identity fields that should stay unique repository-wide
- connector folder basenames, because current CI derives image names from them
"""

import json
from pathlib import Path
from typing import Any

import _matrix_common as common

CONNECTOR_TYPE_DIRS = common.CONNECTOR_TYPE_DIRS

FIELDS_TO_CHECK = ["slug", "container_image"]


def list_manifest_paths_from_fs() -> list[str]:
    paths: list[str] = []
    for connector_type in CONNECTOR_TYPE_DIRS:
        root = Path(connector_type)
        if not root.exists():
            continue
        for entry in root.iterdir():
            if not entry.is_dir() or entry.name.startswith("."):
                continue
            manifest_path = entry / "__metadata__" / "connector_manifest.json"
            if manifest_path.exists():
                paths.append(manifest_path.as_posix())
    return sorted(paths)


def list_connector_dirs_from_fs() -> list[Path]:
    paths: list[Path] = []
    for connector_type in CONNECTOR_TYPE_DIRS:
        root = Path(connector_type)
        if not root.exists():
            continue
        for entry in root.iterdir():
            if entry.is_dir() and not entry.name.startswith("."):
                paths.append(entry)
    return sorted(paths)


def load_json_from_fs(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def collect_duplicates(
    manifests: list[tuple[str, dict[str, Any]]],
) -> dict[str, dict[str, list[str]]]:
    seen: dict[str, dict[str, list[str]]] = {field: {} for field in FIELDS_TO_CHECK}

    for path, data in manifests:
        for field in FIELDS_TO_CHECK:
            raw_value = data.get(field)
            if not isinstance(raw_value, str) or not raw_value.strip():
                raise ValueError(
                    f"{path}: manifest field {field!r} must be a non-empty string"
                )
            value = raw_value.strip()
            seen[field].setdefault(value, []).append(path)

    duplicates: dict[str, dict[str, list[str]]] = {
        field: {} for field in FIELDS_TO_CHECK
    }
    for field in FIELDS_TO_CHECK:
        for value, paths in seen[field].items():
            if len(paths) > 1:
                duplicates[field][value] = sorted(paths)
    return duplicates


def collect_folder_name_duplicates(connector_dirs: list[Path]) -> dict[str, list[str]]:
    seen: dict[str, list[str]] = {}
    for connector_dir in connector_dirs:
        seen.setdefault(connector_dir.name, []).append(connector_dir.as_posix())

    duplicates: dict[str, list[str]] = {}
    for name, paths in seen.items():
        if len(paths) > 1:
            duplicates[name] = sorted(paths)
    return duplicates


def main() -> int:
    connector_dirs = list_connector_dirs_from_fs()
    manifests = [
        (path, load_json_from_fs(path)) for path in list_manifest_paths_from_fs()
    ]
    duplicates = collect_duplicates(manifests)
    folder_duplicates = collect_folder_name_duplicates(connector_dirs)

    has_failure = any(duplicates[field] for field in FIELDS_TO_CHECK) or bool(
        folder_duplicates
    )
    if not has_failure:
        print("No connector identity duplicates detected.")
        return 0

    print("Found connector identity duplicate issues:")
    for folder_name, paths in sorted(folder_duplicates.items()):
        print(f"- [folder_name] {folder_name}")
        for path in paths:
            print(f"  - {path}")

    for field in FIELDS_TO_CHECK:
        for value, paths in sorted(duplicates[field].items()):
            print(f"- [{field}] {value}")
            for path in paths:
                print(f"  - {path}")

    print("\nFix by ensuring each connector has unique manifest values for:")
    print("- connector folder basename (used by CI to build Docker image names)")
    print("- slug")
    print("- container_image")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
