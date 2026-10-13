#!/usr/bin/env python3
"""Scan a single connector for dependency issues with deptry.

Usage: deptry_scan.py <connector-dir>          # e.g. external-import/foo

Environment:
  DEPTRY_MAP_FILE     package/module map + ignore list (default: .github/deptry-package-map.txt)
  DEPTRY_RESULTS_DIR  directory where <name>.err / <name>.warn are written (default: a temp dir)

deptry runs inside an isolated uv environment with the connector's own
dependencies installed, so transitive imports (provided by pycti) are reported
as DEP003 instead of false DEP001.

Exit codes:
  0  deptry ran; no undeclared dependency (DEP001)
  1  deptry ran; at least one undeclared dependency (DEP001) -> blocking
  2  deptry could not run (environment build failure / crash) -> blocking
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

DEPTRY_VERSION = "deptry==0.25.1"


def annotate(line: str) -> None:
    """Emit a GitHub Actions annotation only when running inside Actions."""
    if os.environ.get("GITHUB_ACTIONS"):
        print(line)


def load_config(map_file: Path) -> tuple[str, str]:
    """Return (package->module map, DEP002 ignore list) as deptry CLI strings.

    deptry MAPPING options replace the whole dict on each flag, so all entries
    must be joined into a single argument.
    """
    map_entries: list[str] = []
    ignore_pkgs: list[str] = []
    if map_file.is_file():
        for raw in map_file.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("ignore="):
                ignore_pkgs.append(line[len("ignore=") :])
            else:
                map_entries.append(line)
    return ",".join(map_entries), "|".join(ignore_pkgs)


# Directories that never contain first-party source (also excluded from deptry).
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}


def first_party_modules(root: Path) -> list[str]:
    """Every local package/module name anywhere in the connector, so intra-connector
    imports (even across non-standard layouts) are never mistaken for missing
    dependencies."""
    names = {"src"}
    for path in root.rglob("*"):
        parts = path.relative_to(root).parts
        if any(
            p in SKIP_DIRS or p.startswith(".") or p.endswith(".egg-info")
            for p in parts
        ):
            continue
        if path.is_dir():
            names.add(path.name)
        elif path.suffix == ".py":
            names.add(path.stem)
    return sorted(names)


def declared_line(declared_in: Path, package: str) -> int:
    """First line mentioning the package in the dependency file (deptry does not
    report a line for DEP002). Works for both requirements.txt and pyproject.toml."""
    pattern = re.compile(
        rf"""(^|[\s"']){re.escape(package)}([\s"'\[=<>~!]|$)""", re.IGNORECASE
    )
    for i, line in enumerate(declared_in.read_text().splitlines(), start=1):
        if pattern.search(line):
            return i
    return 1


def resolve_requirements(
    connector: Path, tmp: Path
) -> tuple[Path, Path] | tuple[None, None]:
    """Return (requirements_file, declared_in) for the connector.

    Uses a requirements.txt when present, otherwise generates one from the
    [project.dependencies] of a pyproject.toml, so connectors that declare their
    dependencies there are covered too.
    """
    for req in (connector / "src" / "requirements.txt", connector / "requirements.txt"):
        if req.is_file():
            return req, req

    for pyproject in (
        connector / "pyproject.toml",
        connector / "src" / "pyproject.toml",
    ):
        if not pyproject.is_file():
            continue
        deps = (
            tomllib.loads(pyproject.read_text())
            .get("project", {})
            .get("dependencies", [])
        )
        if not deps:
            continue
        generated = tmp / "requirements.txt"
        generated.write_text("\n".join(deps) + "\n")
        return generated, pyproject

    return None, None


def run_deptry(src: Path, req: Path, tmp: Path) -> list[dict] | None:
    """Run deptry in an isolated uv env; return parsed issues, or None if it
    could not run (environment build failure / crash)."""
    package_map, dep002_ignores = load_config(
        Path(os.environ.get("DEPTRY_MAP_FILE", ".github/deptry-package-map.txt"))
    )
    # __main__ is a pydantic BaseSettings false positive; DEP002 ignores from config.
    per_rule = "DEP001=__main__"
    if dep002_ignores:
        per_rule += f",DEP002={dep002_ignores}"

    kf_args: list[str] = []
    for module in first_party_modules(src):
        kf_args += ["--known-first-party", module]

    report = tmp / "report.json"
    cmd = [
        "uv",
        "run",
        "--isolated",
        "--no-project",
        "--with-requirements",
        str(req),
        "--with",
        DEPTRY_VERSION,
        "--",
        "deptry",
        str(src),
        "--requirements-files",
        str(req),
        "--json-output",
        str(report),
        "--extend-exclude",
        r".*/tests?/.*",
        "--extend-exclude",
        r".*_tests?/.*",
        "--extend-exclude",
        r".*\.egg-info/.*",
        "--per-rule-ignores",
        per_rule,
        *kf_args,
    ]
    if package_map:
        cmd += ["--package-module-name-map", package_map]

    proc = subprocess.run(cmd, capture_output=True, text=True)

    # deptry writes the JSON report (even "[]") whenever it runs. A missing or
    # invalid report means the environment failed to build or deptry crashed.
    try:
        return json.loads(report.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: deptry_scan.py <connector-dir>", file=sys.stderr)
        return 2

    connector = sys.argv[1].rstrip("/")
    connector_path = Path(connector)
    name = connector.replace("/", "_")
    results_dir = Path(os.environ.get("DEPTRY_RESULTS_DIR") or tempfile.mkdtemp())

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        req, declared_in = resolve_requirements(connector_path, tmp)
        if req is None:
            print(
                f"No requirements.txt or pyproject.toml deps for {connector}, skipping."
            )
            return 0
        # Scan the whole connector so every layout is covered; tests, venv and
        # build artefacts are excluded by deptry.
        issues = run_deptry(connector_path, req, tmp)

    if issues is None:
        annotate(
            f"::error title=deptry could not run::Failed to build the "
            f"environment or run deptry for {connector}"
        )
        print(f"deptry did not run for {connector}", file=sys.stderr)
        return 2

    results_dir.mkdir(parents=True, exist_ok=True)
    err_file = results_dir / f"{name}.err"
    warn_file = results_dir / f"{name}.warn"
    has_dep001 = False

    for issue in issues:
        code = issue.get("error", {}).get("code", "")
        module = issue.get("module", "")
        loc = issue.get("location") or {}
        file = loc.get("file") or str(declared_in)
        line = loc.get("line") or 1

        if code == "DEP001":
            annotate(
                f"::error file={file},line={line},title=Undeclared dependency::"
                f"{module} is imported but not declared in {declared_in}"
            )
            with err_file.open("a") as fh:
                fh.write(
                    f"- `{module}` (DEP001) in `{connector}`: "
                    f"imported but not declared in `{declared_in}`\n"
                )
            has_dep001 = True
        elif code == "DEP003":
            annotate(
                f"::warning file={file},line={line},title=Transitive dependency::"
                f"{module} is imported but only available transitively; add it to {declared_in}"
            )
            with warn_file.open("a") as fh:
                fh.write(f"- `{module}` (DEP003, transitive) in `{declared_in}`\n")
        elif code == "DEP002":
            line = declared_line(declared_in, module)
            annotate(
                f"::warning file={declared_in},line={line},title=Unused dependency::"
                f"{module} is listed in {declared_in} but not imported in {connector}"
            )
            with warn_file.open("a") as fh:
                fh.write(f"- `{module}` (DEP002, unused) in `{declared_in}`\n")

    return 1 if has_dep001 else 0


if __name__ == "__main__":
    sys.exit(main())
