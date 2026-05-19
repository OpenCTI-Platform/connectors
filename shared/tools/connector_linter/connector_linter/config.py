"""Project-level configuration via ``pyproject.toml``.

Reads ``[tool.connector-linter]`` from the connector's ``pyproject.toml`` (or
a parent directory) and exposes it as a typed :class:`LinterConfig` object.

Inspired by Ruff's configuration model::

    [tool.connector-linter]
    select = ["VC1xx", "VC3xx"]        # only run these checks/prefixes
    ignore = ["VC306", "VC307"]        # skip these checks
    per-file-ignores = {"tests/*.py" = ["VC309"]}

CLI flags always take precedence over ``pyproject.toml`` values.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import]
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[import,no-redef]


@dataclass
class LinterConfig:
    """Parsed project-level linter configuration."""

    select: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)
    per_file_ignores: dict[str, list[str]] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        """Return True if no configuration was specified."""
        return not self.select and not self.ignore and not self.per_file_ignores


def _find_pyproject(start: Path) -> Path | None:
    """Walk up from *start* looking for ``pyproject.toml``.

    Stops at the filesystem root. Returns ``None`` if not found.
    """
    candidate = start.resolve()
    while True:
        pyproject = candidate / "pyproject.toml"
        if pyproject.is_file():
            return pyproject
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    return None


def _parse_table(table: dict[str, Any]) -> LinterConfig:
    """Parse a ``[tool.connector-linter]`` table into :class:`LinterConfig`."""
    select = table.get("select", [])
    ignore = table.get("ignore", [])
    raw_pfi = table.get("per-file-ignores", {})

    if not isinstance(select, list):
        select = []
    if not isinstance(ignore, list):
        ignore = []
    if not isinstance(raw_pfi, dict):
        raw_pfi = {}

    per_file_ignores: dict[str, list[str]] = {}
    for pattern, codes in raw_pfi.items():
        if isinstance(codes, list):
            per_file_ignores[pattern] = [str(c) for c in codes]

    return LinterConfig(
        select=[str(s) for s in select],
        ignore=[str(i) for i in ignore],
        per_file_ignores=per_file_ignores,
    )


def load_config(connector_path: Path, config_path: Path | None = None) -> LinterConfig:
    """Load linter configuration from ``pyproject.toml``.

    Args:
        connector_path: Root directory of the connector being checked.
        config_path: Explicit path to a ``pyproject.toml`` file. If ``None``,
            searches upward from *connector_path*.

    Returns:
        Parsed :class:`LinterConfig`. Returns an empty config if no file
        is found or the ``[tool.connector-linter]`` section is missing.
    """
    if config_path is not None:
        pyproject = config_path.resolve()
        if not pyproject.is_file():
            return LinterConfig()
    else:
        pyproject = _find_pyproject(connector_path)

    if pyproject is None:
        return LinterConfig()

    try:
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return LinterConfig()

    tool_table = data.get("tool", {})
    linter_table = tool_table.get("connector-linter", None)
    if linter_table is None:
        return LinterConfig()

    return _parse_table(linter_table)


def get_per_file_ignores(
    config: LinterConfig,
    file_path: Path,
    connector_root: Path,
) -> set[str]:
    """Return the set of check codes to ignore for a specific file.

    Glob patterns in ``per-file-ignores`` are matched against the file path
    relative to the connector root. Both forward-slash and OS-native separators
    are supported.
    """
    if not config.per_file_ignores:
        return set()

    try:
        rel = file_path.relative_to(connector_root)
    except ValueError:
        rel = file_path

    rel_str = str(rel)
    # Normalise to forward-slash for consistent glob matching
    rel_posix = rel_str.replace("\\", "/")

    codes: set[str] = set()
    for pattern, pattern_codes in config.per_file_ignores.items():
        if fnmatch(rel_posix, pattern) or fnmatch(rel_posix, f"**/{pattern}"):
            codes.update(pattern_codes)
    return codes
