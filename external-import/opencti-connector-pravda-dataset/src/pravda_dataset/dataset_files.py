from __future__ import annotations

from pathlib import Path


def _is_under_root(root: Path, candidate: Path) -> bool:
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    try:
        return candidate_resolved.is_relative_to(root_resolved)
    except AttributeError:
        # Python < 3.9 fallback
        return str(candidate_resolved).startswith(str(root_resolved))


def discover_dataset_files(dataset_root: Path) -> list[Path]:
    root_resolved = dataset_root.resolve()
    if not root_resolved.exists() or not root_resolved.is_dir():
        return []

    results: list[Path] = []
    for path in root_resolved.rglob("*"):
        if not path.is_file():
            continue

        is_csv = path.suffix.lower() == ".csv"
        is_csv_gz = [s.lower() for s in path.suffixes[-2:]] == [".csv", ".gz"]
        if not (is_csv or is_csv_gz):
            continue

        resolved = path.resolve()
        if not _is_under_root(root_resolved, resolved):
            continue

        results.append(resolved)

    results.sort()
    return results
