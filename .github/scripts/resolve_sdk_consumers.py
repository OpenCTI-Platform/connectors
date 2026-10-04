#!/usr/bin/env python3
"""Check that every connector depending on connectors-sdk still resolves with the SDK of this checkout.

A dependency pin added to connectors-sdk/pyproject.toml can conflict with a pin of a connector that nothing in the
pull request touches: the connector is not rebuilt on the pull request, and master goes red at the next full build.
This script rewrites each consumer's dependency declaration so that the SDK comes from the local checkout, resolves
it with `uv pip compile` (no installation) for the Python version the connector image runs, and reports every
connector whose dependency set became unsatisfiable.

Consumers are the connectors whose `requirements.txt`, `src/requirements.txt`, `pyproject.toml` or
`src/pyproject.toml` installs `connectors-sdk` from this repository. The Python version comes from the connector's
Dockerfile (`FROM python:3.11-alpine`, `python3.12` on ubi9 images); 3.12 is the fallback.

Usage: resolve_sdk_consumers.py [--jobs 8] [--sdk connectors-sdk] [--python 3.12] [--only <path> ...]
Exit code 1 when at least one consumer does not resolve.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib

SDK_GIT_REQUIREMENT = re.compile(
    r"connectors-sdk\s*@\s*git\+https://github\.com/OpenCTI-Platform/connectors(\.git)?"
    r"@[^#\s\"']+#subdirectory=connectors-sdk",
    re.IGNORECASE,
)
DOCKERFILE_PYTHON = re.compile(r"\bpython(?::|3\.)?(3\.\d{1,2})", re.IGNORECASE)
CONNECTOR_DIRS = (
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-hunt",
    "internal-import-file",
    "stream",
    "templates",
)
DEPENDENCY_FILES = (
    "requirements.txt",
    "src/requirements.txt",
    "pyproject.toml",
    "src/pyproject.toml",
)


def read_text(path: pathlib.Path) -> str:
    """Read a text file, tolerating the odd non UTF-8 byte."""
    return path.read_text(encoding="utf-8", errors="replace")


def consumers(root: pathlib.Path) -> list[pathlib.Path]:
    """Return every dependency file that installs connectors-sdk from this repository."""
    found: list[pathlib.Path] = []
    for family in CONNECTOR_DIRS:
        base = root / family
        if not base.is_dir():
            continue
        for connector in sorted(p for p in base.iterdir() if p.is_dir()):
            for relative in DEPENDENCY_FILES:
                candidate = connector / relative
                if candidate.is_file() and SDK_GIT_REQUIREMENT.search(
                    read_text(candidate)
                ):
                    found.append(candidate)
    return found


def connector_dir(dependency_file: pathlib.Path) -> pathlib.Path:
    """Return the connector directory of a dependency file (its parent, or the parent of `src`)."""
    parent = dependency_file.parent
    return parent.parent if parent.name == "src" else parent


def dockerfile_versions(paths: list[pathlib.Path]) -> set[str]:
    """Return every Python version stated by the given Dockerfiles (`FROM python:3.11-alpine`, `python3.12`)."""
    found: set[str] = set()
    for dockerfile in paths:
        for line in read_text(dockerfile).splitlines():
            if not line.lstrip().upper().startswith("FROM") and "python" not in line:
                continue
            match = DOCKERFILE_PYTHON.search(line)
            if match:
                found.add(match.group(1))
    return found


def python_versions(
    dependency_file: pathlib.Path, root: pathlib.Path, fallback: str
) -> list[str]:
    """Return the Python versions a connector is built with.

    A connector is built from its own Dockerfile(s) (alpine images, `FROM python:3.11-alpine`) and
    from the shared `Dockerfile_ubi9` at the repository root (`python3.12`), so both versions have
    to resolve. The fallback applies only when no Dockerfile states a version.
    """
    directory = connector_dir(dependency_file)
    versions = dockerfile_versions(sorted(directory.glob("Dockerfile*")))
    versions |= dockerfile_versions(sorted(root.glob("Dockerfile_ubi9*")))
    return sorted(versions) or [fallback]


def rewrite_sdk_requirement(text: str, sdk: pathlib.Path) -> str:
    """Point the SDK requirement at the local checkout instead of the git repository."""
    return SDK_GIT_REQUIREMENT.sub(f"connectors-sdk @ {sdk.resolve().as_uri()}", text)


def requirement_lines(dependency_file: pathlib.Path) -> list[str]:
    """Return the runtime requirements declared by a requirements.txt or a pyproject.toml.

    A pyproject.toml is reduced to its `[project].dependencies` so that uv resolves a plain
    requirement list: project and workspace semantics (`[tool.uv.workspace]`, path sources)
    are irrelevant to the question asked here and break when the file is copied elsewhere.
    """
    text = read_text(dependency_file)
    if dependency_file.name != "pyproject.toml":
        return text.splitlines()
    project = tomllib.loads(text).get("project", {})
    return list(project.get("dependencies", []))


def resolve(
    dependency_file: pathlib.Path,
    version: str,
    sdk: pathlib.Path,
    root: pathlib.Path,
) -> tuple[pathlib.Path, str, bool, str]:
    """Resolve one dependency file for one Python version with the SDK taken from the local checkout."""
    rewritten = rewrite_sdk_requirement(
        "\n".join(requirement_lines(dependency_file)), sdk
    )
    with tempfile.TemporaryDirectory(prefix="sdk-consumer-") as workdir:
        temp_input = pathlib.Path(workdir) / "requirements.txt"
        temp_input.write_text(rewritten + "\n", encoding="utf-8")
        # uv writes the lock atomically (temporary file + rename): the output must be a real file
        completed = subprocess.run(
            [
                "uv",
                "pip",
                "compile",
                str(temp_input),
                "--python-version",
                version,
                "--quiet",
                "--no-header",
                "--no-annotate",
                "--output-file",
                str(pathlib.Path(workdir) / "resolved.txt"),
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
    detail = (completed.stderr or completed.stdout).strip()
    return dependency_file.relative_to(root), version, completed.returncode == 0, detail


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--python",
        default="3.12",
        help="Python version used when a connector has no Dockerfile stating one (default 3.12)",
    )
    parser.add_argument(
        "--jobs", type=int, default=8, help="parallel resolutions (default 8)"
    )
    parser.add_argument(
        "--sdk",
        default="connectors-sdk",
        help="path of the SDK to test (default connectors-sdk)",
    )
    parser.add_argument(
        "--only",
        nargs="*",
        default=None,
        help="dependency files to check instead of discovering them",
    )
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parents[2]
    sdk = (root / args.sdk).resolve()
    if not (sdk / "pyproject.toml").is_file():
        print(f"no SDK at {sdk}", file=sys.stderr)
        return 2
    files = (
        [pathlib.Path(p).resolve() for p in args.only] if args.only else consumers(root)
    )
    # one resolution per (dependency file, Python version the connector is built with)
    targets = [
        (dependency_file, version)
        for dependency_file in files
        for version in python_versions(dependency_file, root, args.python)
    ]
    print(
        f"Resolving {len(files)} dependency file(s) of connectors that depend on connectors-sdk "
        f"with the SDK of this checkout ({len(targets)} resolutions, one per Python version each "
        f"connector is built with)"
    )

    failures: list[tuple[pathlib.Path, str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = pool.map(lambda t: resolve(t[0], t[1], sdk, root), targets)
        for path, version, ok, detail in results:
            if ok:
                print(f"  ok   py{version}  {path}")
            else:
                failures.append((path, version, detail))
                print(f"  FAIL py{version}  {path}")

    if failures:
        print(f"\n{len(failures)} connector(s) no longer resolve with this SDK:\n")
        for path, version, detail in failures:
            print(f"== {path} (python {version})")
            for line in detail.splitlines()[-12:]:
                print(f"   {line}")
        print(
            "\nA dependency pin of connectors-sdk conflicts with a pin of these connectors. "
            "Loosen the SDK pin to a version every consumer accepts, or update the connectors "
            "in the same pull request."
        )
        return 1
    print("\nEvery SDK consumer resolves.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
