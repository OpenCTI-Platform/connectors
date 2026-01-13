from __future__ import annotations

"""Dataset file discovery utilities.

The Checkfirst connector ingests CSV files from a dataset directory. This module is
responsible for finding candidate files under a configured dataset root.

Notes:
- Only `.csv` and `.csv.gz` files are considered.
- Results are returned as resolved absolute paths and sorted for determinism.
"""

from pathlib import Path


def _is_under_root(root: Path, candidate: Path) -> bool:
    """Return True if `candidate` is located under `root` (after resolving)."""
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    try:
        return candidate_resolved.is_relative_to(root_resolved)
    except AttributeError:
        # Python < 3.9 fallback
        return str(candidate_resolved).startswith(str(root_resolved))


def discover_dataset_files(dataset_root: Path) -> list[Path]:
    """Discover dataset files under `dataset_root`.

    Returns an empty list if the root does not exist or is not a directory.
    """
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
        # Guard against odd filesystem behaviors (symlinks, traversal) by ensuring
        # the resolved path remains under the configured dataset root.
        if not _is_under_root(root_resolved, resolved):
            continue

        results.append(resolved)

    results.sort()
    return results
