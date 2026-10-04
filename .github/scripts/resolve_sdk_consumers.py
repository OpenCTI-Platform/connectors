#!/usr/bin/env python3
"""Check that every connector depending on connectors-sdk still resolves with the SDK of this checkout.

A dependency pin added to connectors-sdk/pyproject.toml can conflict with a pin of a connector that nothing in the
pull request touches: the connector is not rebuilt on the pull request, and master goes red at the next full build.
This script rewrites each consumer's requirements so that the SDK comes from the local checkout, resolves them with
`uv pip compile` (no installation) and reports every connector whose dependency set became unsatisfiable.

Usage: resolve_sdk_consumers.py [--python 3.12] [--jobs 8] [--sdk connectors-sdk] [--only <path> ...]
Exit code 1 when at least one consumer does not resolve.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import pathlib
import re
import subprocess
import sys
import tempfile

SDK_REQUIREMENT = re.compile(
    r"^\s*connectors-sdk\s*@\s*git\+https://github\.com/OpenCTI-Platform/connectors(\.git)?@[^#\s]+#subdirectory=connectors-sdk\s*$",
    re.IGNORECASE,
)
CONNECTOR_DIRS = (
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-hunt",
    "internal-import-file",
    "stream",
    "templates",
)


def consumers(root: pathlib.Path) -> list[pathlib.Path]:
    """Return every requirements file that installs connectors-sdk from this repository."""
    found: list[pathlib.Path] = []
    for family in CONNECTOR_DIRS:
        base = root / family
        if not base.is_dir():
            continue
        for candidate in sorted(list(base.glob("*/requirements.txt")) + list(base.glob("*/src/requirements.txt"))):
            try:
                text = candidate.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = candidate.read_text(encoding="latin-1")
            if any(SDK_REQUIREMENT.match(line) for line in text.splitlines()):
                found.append(candidate)
    return found


def resolve(requirements: pathlib.Path, sdk: pathlib.Path, python: str, root: pathlib.Path) -> tuple[pathlib.Path, bool, str]:
    """Resolve one requirements file with the SDK taken from the local checkout."""
    lines = requirements.read_text(encoding="utf-8", errors="replace").splitlines()
    rewritten = [
        f"connectors-sdk @ {sdk.resolve().as_uri()}" if SDK_REQUIREMENT.match(line) else line for line in lines
    ]
    with tempfile.TemporaryDirectory(prefix="sdk-consumer-") as workdir:
        temp_requirements = pathlib.Path(workdir) / "requirements.txt"
        temp_requirements.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        # uv writes the lock atomically (temporary file + rename), so the output must be a real file, not /dev/null
        completed = subprocess.run(
            [
                "uv", "pip", "compile", str(temp_requirements),
                "--python-version", python,
                "--quiet", "--no-header", "--no-annotate",
                "--output-file", str(pathlib.Path(workdir) / "resolved.txt"),
            ],
            capture_output=True, text=True, timeout=600,
        )
    detail = (completed.stderr or completed.stdout).strip()
    return requirements.relative_to(root), completed.returncode == 0, detail


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--python", default="3.12", help="Python version the connector images run (default 3.12)")
    parser.add_argument("--jobs", type=int, default=8, help="parallel resolutions (default 8)")
    parser.add_argument("--sdk", default="connectors-sdk", help="path of the SDK to test (default connectors-sdk)")
    parser.add_argument("--only", nargs="*", default=None, help="requirements files to check instead of discovering them")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parents[2]
    sdk = (root / args.sdk).resolve()
    if not (sdk / "pyproject.toml").is_file():
        print(f"no SDK at {sdk}", file=sys.stderr)
        return 2
    targets = [pathlib.Path(p).resolve() for p in args.only] if args.only else consumers(root)
    print(f"Resolving {len(targets)} connector(s) that depend on connectors-sdk with the SDK of this checkout (python {args.python})")

    failures: list[tuple[pathlib.Path, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for path, ok, detail in pool.map(lambda t: resolve(t, sdk, args.python, root), targets):
            if ok:
                print(f"  ok   {path}")
            else:
                failures.append((path, detail))
                print(f"  FAIL {path}")

    if failures:
        print(f"\n{len(failures)} connector(s) no longer resolve with this SDK:\n")
        for path, detail in failures:
            print(f"== {path}")
            for line in detail.splitlines()[-12:]:
                print(f"   {line}")
        print(
            "\nA dependency pin of connectors-sdk conflicts with a pin of these connectors. Loosen the SDK pin to a version "
            "every consumer accepts, or update the connectors in the same pull request."
        )
        return 1
    print("\nEvery SDK consumer resolves.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
