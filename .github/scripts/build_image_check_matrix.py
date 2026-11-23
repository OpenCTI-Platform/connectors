#!/usr/bin/env python3
"""
Generate the matrix of connector images to test-build in the merge queue.

The image builds of build-all-connectors.yml only run after a commit lands
on master, so a broken image (e.g. a dependency bump needing a system
package missing from the UBI9 base) used to be found only once merged.
ci-build-images.yml runs this script on merge_group events and builds,
without pushing, the images a merge would build, so the queue rejects the
PR instead.

Only the connectors whose own directory changed between DIFF_BASE and
DIFF_HEAD are built, with the same variants and platforms as on master:
  - Alpine image (the connector's Dockerfile), amd64 and arm64. The FIPS
    image is built by the amd64 job when Dockerfile_fips exists.
  - UBI9 image (shared Dockerfile_ubi9), amd64 and arm64, for connectors
    listed in .github/ubi9-connectors.json. A change to Dockerfile_ubi9
    itself selects every UBI9 connector, and a connector newly added to
    ubi9-connectors.json is selected even if its directory is unchanged.
A change to the build tooling (build action, retry script, this check)
adds one canary connector, so a broken tooling change cannot pass the
queue just because no connector changed alongside it.

Unlike build_alpine_matrix.py, a change to connectors-sdk/, shared/ or the
build tooling does NOT select every connector: the rolling build installs
connectors-sdk from the base branch anyway, and rebuilding ~300 images per
merge would cost more than the master build it protects. Above MAX_JOBS
build jobs (release commits, repo-wide dependency bumps) nothing is built
and a warning is emitted; master still builds them. The default fits a
Dockerfile_ubi9 change (40 connectors x 2 platforms) and ~25 connectors
with both variants.

Environment:
  DIFF_BASE  - base commit (merge_group.base_sha). Required.
  DIFF_HEAD  - head commit (default: HEAD).
  MAX_JOBS   - cap on the number of build jobs (default: 100).

Outputs ($GITHUB_OUTPUT):
  - matrix:     {"include": [...]} with one entry per image and platform
  - has_builds: "true" or "false"
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import _matrix_common as common
from build_alpine_matrix import discover_connectors, get_changed_connectors

UBI9_CONNECTORS_FILE = Path(".github/ubi9-connectors.json")
UBI9_DOCKERFILE = "Dockerfile_ubi9"
DEFAULT_MAX_JOBS = 100

# Built when the tooling changes; listed in ubi9-connectors.json so both
# variants are exercised.
CANARY_CONNECTOR = "external-import/mitre"
BUILD_TOOLING_PATHS = (
    ".github/actions/build-connector-image/",
    ".github/scripts/buildx_with_retry.sh",
    ".github/scripts/build_image_check_matrix.py",
    # Imported by this script.
    ".github/scripts/build_alpine_matrix.py",
    ".github/scripts/_matrix_common.py",
    # Called by the build action to resolve RELEASE_REF.
    "shared/tools/ci/detect-base-branch.sh",
    ".github/workflows/ci-build-images.yml",
)

PLATFORMS = [
    {"arch": "amd64", "platform": "linux/amd64", "runner": "ubuntu-latest"},
    {"arch": "arm64", "platform": "linux/arm64", "runner": "ubuntu-24.04-arm"},
]


def get_changed_files(base: str, head: str) -> set[str]:
    """Files changed between *base* and *head*. Exits on git failure."""
    result = subprocess.run(
        ["git", "-c", "core.quotePath=false", "diff", "--name-only", "--no-renames"]
        + [base, head],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Failing loudly beats building nothing: a silent empty matrix would
        # let a broken image through the queue.
        print(f"::error::git diff {base} {head} failed: {result.stderr.strip()}")
        sys.exit(1)
    return set(result.stdout.splitlines())


def load_ubi9_connectors() -> list[str]:
    return json.loads(UBI9_CONNECTORS_FILE.read_text())


def added_ubi9_connectors(base: str, changed_files: set[str]) -> set[str]:
    """Entries of ubi9-connectors.json that are new since *base*.

    Master builds every listed connector, so a connector added to the list
    gets its first UBI9 image on the next master build: check it here.
    """
    if UBI9_CONNECTORS_FILE.as_posix() not in changed_files:
        return set()
    result = subprocess.run(
        ["git", "show", f"{base}:{UBI9_CONNECTORS_FILE.as_posix()}"],
        capture_output=True,
        text=True,
    )
    # The file did not exist at base: every entry is new.
    base_paths = set(json.loads(result.stdout)) if result.returncode == 0 else set()
    added = set(load_ubi9_connectors()) - base_paths
    if added:
        print(f"  ➕ Added to {UBI9_CONNECTORS_FILE.name}: {sorted(added)}")
    return added


def select_images(
    changed_files: set[str],
    alpine_by_path: dict[str, dict],
    ubi9_paths: list[str],
    ubi9_added: set[str],
) -> tuple[list[dict], list[dict]]:
    """Return (alpine, ubi9) connector entries to build."""
    changed_connectors = get_changed_connectors(changed_files)
    if any(f.startswith(BUILD_TOOLING_PATHS) for f in changed_files):
        print(f"  🔧 Build tooling changed → canary {CANARY_CONNECTOR}")
        changed_connectors.add(CANARY_CONNECTOR)

    alpine = [
        alpine_by_path[p] for p in sorted(changed_connectors & alpine_by_path.keys())
    ]

    if UBI9_DOCKERFILE in changed_files:
        print(f"  🔄 {UBI9_DOCKERFILE} changed → every UBI9 connector")
        ubi9_selected = set(ubi9_paths)
    else:
        ubi9_selected = (changed_connectors | ubi9_added) & set(ubi9_paths)
    # A connector removed by the change has nothing left to build.
    ubi9 = [
        {"path": p, "name": Path(p).name}
        for p in sorted(ubi9_selected)
        if Path(p).is_dir()
    ]
    return alpine, ubi9


def matrix_entries(alpine: list[dict], ubi9: list[dict]) -> list[dict]:
    entries = []
    for c in alpine:
        for plat in PLATFORMS:
            entries.append(
                {
                    "variant": "alpine",
                    "path": c["path"],
                    "name": c["name"],
                    "dockerfile": "",
                    "build_variant": "",
                    "fips": c["fips"],
                    **plat,
                }
            )
    for c in ubi9:
        for plat in PLATFORMS:
            entries.append(
                {
                    "variant": "ubi9",
                    "path": c["path"],
                    "name": c["name"],
                    "dockerfile": UBI9_DOCKERFILE,
                    "build_variant": "ubi9",
                    "fips": "false",
                    **plat,
                }
            )
    return entries


def write_matrix(entries: list[dict]) -> None:
    common.write_output(
        "matrix", json.dumps({"include": entries}, separators=(",", ":"))
    )
    common.write_output("has_builds", "true" if entries else "false")


def main() -> None:
    base = os.environ.get("DIFF_BASE", "")
    if not base:
        print("::error::DIFF_BASE is required")
        sys.exit(1)
    head = os.environ.get("DIFF_HEAD") or "HEAD"
    max_jobs = int(os.environ.get("MAX_JOBS") or DEFAULT_MAX_JOBS)

    changed_files = get_changed_files(base, head)
    print(f"{len(changed_files)} files changed between {base[:12]} and {head[:12]}")

    alpine_by_path = {
        c["path"]: c for entries in discover_connectors().values() for c in entries
    }
    alpine, ubi9 = select_images(
        changed_files,
        alpine_by_path,
        load_ubi9_connectors(),
        added_ubi9_connectors(base, changed_files),
    )

    entries = matrix_entries(alpine, ubi9)
    if len(entries) > max_jobs:
        common.warn(
            f"{len(entries)} image builds needed (cap {max_jobs}): skipped in the "
            "merge queue, they run on master after merge."
        )
        write_matrix([])
        return

    print(f"  Alpine: {[c['path'] for c in alpine] or 'none'}")
    print(f"  UBI9:   {[c['path'] for c in ubi9] or 'none'}")
    print(f"  {len(entries)} build jobs")
    write_matrix(entries)


if __name__ == "__main__":
    main()
