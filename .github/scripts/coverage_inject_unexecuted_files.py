#!/usr/bin/env python3
"""
Inject all connector .py files into the .coverage database as unexecuted (0%).

Coverage's `source` option discovers files via Python's import system, so it only
finds connectors that are importable packages (i.e. have __init__.py at their root).
This script works around that by walking the source directories with os.walk() and
registering every .py file directly in the .coverage SQLite database via the
CoverageData API. Coverage then re-parses each file's AST at report time to count
executable lines and emits them at 0% in the XML output.

Run AFTER `coverage run noop.py` and BEFORE `coverage xml`.
"""

import fnmatch
import os

from coverage.data import CoverageData

SOURCE_DIRS = [
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
]

OMIT_PATTERNS = ["*/tests/*", "*/test/*", "*/conftest.py"]

SKIP_DIRS = {"__pycache__", ".git", ".venv", "node_modules", ".pytest_cache"}


def should_omit(path: str) -> bool:
    norm = path.replace("\\", "/")
    return any(fnmatch.fnmatch(norm, p) for p in OMIT_PATTERNS)


def main() -> None:
    data = CoverageData(basename=".coverage")
    data.read()
    already_measured: set[str] = set(data.measured_files())

    new_files: dict[str, set] = {}
    for src_dir in SOURCE_DIRS:
        if not os.path.isdir(src_dir):
            print(f"WARNING: source dir not found: {src_dir!r}")
            continue
        for dirpath, dirnames, filenames in os.walk(src_dir, topdown=True):
            dirnames[:] = [
                d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
            ]
            for filename in filenames:
                if not filename.endswith(".py"):
                    continue
                rel = os.path.join(dirpath, filename)
                if should_omit(rel):
                    continue
                abs_path = os.path.abspath(rel)
                if abs_path not in already_measured:
                    new_files[abs_path] = set()

    data.add_lines(new_files)
    data.write()
    print(f"Injected {len(new_files):,} unexecuted files into .coverage")


if __name__ == "__main__":
    main()
