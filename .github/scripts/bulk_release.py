#!/usr/bin/env python3
"""
Bulk connector release resolver.

Resolves a set of connectors (a named list or *all*) and a single shared CalVer
version into the list of per-connector releases to dispatch. It performs **no git
mutations** — it only reads the working tree (and, for idempotency, the remote
tag list) and emits the resolved connector list. The actual release of each
connector (build image, push, create the GitHub Release, which creates the tag)
is performed by the per-connector `release-connector.yml` workflow, which
`release-bulk-connectors.yml` dispatches once per connector.

This read-only design deliberately avoids the fragility of pushing many tags at
once (GitHub drops push events beyond three tags per push, and tags pushed with
GITHUB_TOKEN do not trigger downstream workflows). Each connector is released by
an independent `release-connector.yml` run dispatched via `workflow_dispatch`,
which — unlike tag pushes — always creates a run even when triggered with
GITHUB_TOKEN, and is not subject to the 256-job matrix limit.

Typical use cases:
  - Security fix in a shared dependency → rebuild all affected connectors
  - pycti version bump after a platform release
  - connectors-sdk breaking change
  - LTS alignment (release everything in sync)

Release tag/version format (produced later by release-connector.yml):
    {connector-name}/{MAJOR.YYMMDD.PATCH}     e.g.  mitre/7.260706.0

Examples:
    # Preview the connectors to release for two names
    python bulk_release.py --connectors mitre,crowdstrike

    # Resolve every connector with today's auto-computed CalVer
    python bulk_release.py --all

    # Resolve all connectors for an explicit version, ignoring idempotency
    python bulk_release.py --all --version 7.260706.1 --include-released

Outputs (written to $GITHUB_OUTPUT when set, and always printed as a summary):
    version         the shared CalVer applied to every connector
    connectors      JSON array of connector names to release
    count           number of connectors to release
    skipped         JSON array of connector names skipped (already released)
    skipped_count   number of skipped connectors
    has_connectors  "true" if at least one connector will be released
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path

import _matrix_common as common

# Default CalVer major, matching release-connector.yml (MAJOR=7).
DEFAULT_MAJOR = 7

# CalVer format MAJOR.YYMMDD.PATCH — identical to release-connector.yml.
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]{6}\.[0-9]+$")


class BulkReleaseError(Exception):
    """Raised for user-facing errors (bad input, resolution, matrix overflow)."""


@dataclass(frozen=True)
class Connector:
    """A resolved connector: its short name and repo-relative directory."""

    name: str
    path: str  # e.g. "external-import/mitre"


# ──────────────────────────────────────────────────────────────
# Version helpers
# ──────────────────────────────────────────────────────────────
def compute_calver(
    major: int = DEFAULT_MAJOR, today: datetime.date | None = None
) -> str:
    """Compute today's CalVer as ``MAJOR.YYMMDD.0`` (UTC), matching the workflow."""
    if today is None:
        today = datetime.datetime.now(datetime.timezone.utc).date()
    return f"{major}.{today:%y%m%d}.0"


def validate_version(version: str) -> str:
    """Validate a CalVer string against the release-connector.yml format."""
    if not VERSION_RE.match(version):
        raise BulkReleaseError(
            f"Invalid CalVer version '{version}'. "
            "Expected format: MAJOR.YYMMDD.PATCH (e.g. 7.260706.0)."
        )
    return version


def build_tag(connector_name: str, version: str) -> str:
    """Build the release tag for a connector: ``{name}/{version}``."""
    return f"{connector_name}/{version}"


# ──────────────────────────────────────────────────────────────
# Connector discovery / resolution
# ──────────────────────────────────────────────────────────────
def discover_all_connectors(repo_root: Path) -> list[Connector]:
    """Discover every buildable connector across all type directories.

    A directory is a connector when it lives directly under a type directory,
    does not start with '.' or '_', and contains a ``Dockerfile``. This mirrors
    the CI build matrix (.github/scripts/build_alpine_matrix.py) so that every
    connector the pipeline can build is releasable in bulk.
    """
    connectors: list[Connector] = []
    for type_dir in common.CONNECTOR_TYPE_DIRS:
        type_path = repo_root / type_dir
        if not type_path.is_dir():
            continue
        for connector_path in sorted(type_path.iterdir()):
            if not connector_path.is_dir():
                continue
            if connector_path.name.startswith((".", "_")):
                continue
            if not (connector_path / "Dockerfile").exists():
                continue
            connectors.append(
                Connector(
                    name=connector_path.name,
                    path=f"{type_dir}/{connector_path.name}",
                )
            )
    return sorted(connectors, key=lambda c: c.name)


def find_connector(repo_root: Path, name: str) -> Connector:
    """Resolve a single connector by name, scanning all type directories.

    Raises BulkReleaseError if the name is not found or is ambiguous (present in
    more than one type directory), mirroring release-connector.yml resolution.
    """
    matches = [
        f"{type_dir}/{name}"
        for type_dir in common.CONNECTOR_TYPE_DIRS
        if (repo_root / type_dir / name).is_dir()
    ]
    if not matches:
        raise BulkReleaseError(
            f"Connector '{name}' not found in any type directory "
            f"({', '.join(common.CONNECTOR_TYPE_DIRS)})."
        )
    if len(matches) > 1:
        joined = ", ".join(matches)
        raise BulkReleaseError(
            f"Ambiguous connector name '{name}' — found in multiple "
            f"directories: {joined}."
        )
    return Connector(name=name, path=matches[0])


def resolve_named_connectors(repo_root: Path, names: list[str]) -> list[Connector]:
    """Resolve a list of connector names, aggregating all resolution errors."""
    connectors: list[Connector] = []
    errors: list[str] = []
    for name in names:
        try:
            connectors.append(find_connector(repo_root, name))
        except BulkReleaseError as exc:
            errors.append(str(exc))
    if errors:
        raise BulkReleaseError("\n".join(errors))
    return connectors


def parse_connector_names(raw: str) -> list[str]:
    """Parse a comma-separated connector list into a de-duplicated ordered list."""
    seen: set[str] = set()
    names: list[str] = []
    for chunk in raw.split(","):
        name = chunk.strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    if not names:
        raise BulkReleaseError("No connector names provided in --connectors.")
    return names


# ──────────────────────────────────────────────────────────────
# Git helpers (read-only)
# ──────────────────────────────────────────────────────────────
def resolve_repo_root(explicit: str | None) -> Path:
    """Resolve the repository root from an explicit path or the current git repo."""
    if explicit:
        root = Path(explicit).resolve()
        if not root.is_dir():
            raise BulkReleaseError(f"--repo-root '{explicit}' is not a directory.")
        return root
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise BulkReleaseError(
            "Not inside a git repository. Run from the connectors repo or pass "
            "--repo-root."
        ) from exc
    return Path(result.stdout.strip())


def parse_remote_tags(ls_remote_output: str) -> set[str]:
    """Parse ``git ls-remote --tags`` output into a set of tag names."""
    tags: set[str] = set()
    for line in ls_remote_output.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        ref = parts[1]
        prefix = "refs/tags/"
        if not ref.startswith(prefix):
            continue
        tag = ref[len(prefix) :]
        if tag.endswith("^{}"):  # dereferenced annotated tag entry
            tag = tag[: -len("^{}")]
        tags.add(tag)
    return tags


def get_remote_tags(repo_root: Path, remote: str) -> set[str]:
    """Return the set of tags currently present on the remote (single fetch).

    Read-only. On failure (no network, unknown remote), a warning is printed and
    an empty set is returned so idempotency degrades gracefully rather than
    blocking the resolution.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "ls-remote", "--tags", remote],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        stderr = getattr(exc, "stderr", "") or ""
        print(
            f"⚠️  Could not list tags on remote '{remote}' "
            f"({stderr.strip() or exc}); not skipping any connector.",
            file=sys.stderr,
        )
        return set()
    return parse_remote_tags(result.stdout)


# ──────────────────────────────────────────────────────────────
# Planning / output
# ──────────────────────────────────────────────────────────────
@dataclass
class ReleasePlan:
    """The computed plan: which connectors to release vs. skip."""

    version: str
    pending: list[Connector]  # to release (the matrix)
    skipped: list[Connector]  # already released at this version


def build_plan(
    connectors: list[Connector], version: str, released_tags: set[str]
) -> ReleasePlan:
    """Partition connectors into pending vs. already-released (idempotency)."""
    pending: list[Connector] = []
    skipped: list[Connector] = []
    for connector in connectors:
        if build_tag(connector.name, version) in released_tags:
            skipped.append(connector)
        else:
            pending.append(connector)
    return ReleasePlan(version=version, pending=pending, skipped=skipped)


def print_plan(plan: ReleasePlan) -> None:
    """Print a human-readable summary of the release plan (to stderr)."""
    total = len(plan.pending) + len(plan.skipped)
    print(f"🔖 Bulk release plan (version {plan.version})", file=sys.stderr)
    print(f"  Targets: {total} connector(s)", file=sys.stderr)

    print(f"  To release ({len(plan.pending)}):", file=sys.stderr)
    for connector in plan.pending:
        print(f"    + {build_tag(connector.name, plan.version)}", file=sys.stderr)
    if not plan.pending:
        print("    (none)", file=sys.stderr)

    if plan.skipped:
        print(f"  Already released — skipping ({len(plan.skipped)}):", file=sys.stderr)
        for connector in plan.skipped:
            print(f"    = {build_tag(connector.name, plan.version)}", file=sys.stderr)


def emit_outputs(plan: ReleasePlan, github_output: str | None) -> None:
    """Write GitHub Actions job outputs (and echo them for local runs)."""
    connectors = json.dumps([c.name for c in plan.pending], separators=(",", ":"))
    skipped = json.dumps([c.name for c in plan.skipped], separators=(",", ":"))
    outputs = {
        "version": plan.version,
        "connectors": connectors,
        "count": str(len(plan.pending)),
        "skipped": skipped,
        "skipped_count": str(len(plan.skipped)),
        "has_connectors": "true" if plan.pending else "false",
    }

    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")

    print("📤 Outputs:", file=sys.stderr)
    for key, value in outputs.items():
        print(f"  {key}={value}", file=sys.stderr)


# ──────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bulk_release.py",
        description="Resolve connectors into a bulk-release build matrix.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--connectors",
        metavar="NAME1,NAME2",
        help="Comma-separated connector names to release (e.g. 'mitre,crowdstrike').",
    )
    target.add_argument(
        "--all",
        action="store_true",
        help="Release every connector (all type directories, regardless of changes).",
    )
    parser.add_argument(
        "--version",
        default="",
        help="CalVer version to tag, same for all connectors (e.g. 7.260706.0). "
        "Defaults to today's auto-computed 7.YYMMDD.0.",
    )
    parser.add_argument(
        "--major",
        type=int,
        default=DEFAULT_MAJOR,
        help=f"CalVer major used when auto-computing the version (default: {DEFAULT_MAJOR}).",
    )
    parser.add_argument(
        "--remote",
        default="origin",
        help="Git remote inspected for already-released tags (default: origin).",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Path to the connectors repo root (default: auto-detected via git).",
    )
    parser.add_argument(
        "--include-released",
        action="store_true",
        help="Do not skip connectors already released at this version "
        "(disables idempotency filtering; useful for a full dry-run preview).",
    )
    parser.add_argument(
        "--github-output",
        default=os.environ.get("GITHUB_OUTPUT"),
        help="Path to write matrix outputs (defaults to $GITHUB_OUTPUT).",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    repo_root = resolve_repo_root(args.repo_root)

    version = (
        validate_version(args.version) if args.version else compute_calver(args.major)
    )

    if args.all:
        connectors = discover_all_connectors(repo_root)
        if not connectors:
            raise BulkReleaseError(
                f"No connectors discovered under {repo_root}. "
                "Are you pointing at the connectors repo root?"
            )
    else:
        connectors = resolve_named_connectors(
            repo_root, parse_connector_names(args.connectors)
        )

    released_tags: set[str] = set()
    if not args.include_released:
        released_tags = get_remote_tags(repo_root, args.remote)

    plan = build_plan(connectors, version, released_tags)

    print_plan(plan)
    emit_outputs(plan, args.github_output)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        return run(args)
    except BulkReleaseError as exc:
        print(f"❌ {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
