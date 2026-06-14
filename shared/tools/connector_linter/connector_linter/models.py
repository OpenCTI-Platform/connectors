"""Data models for the connector linter."""

import ast
import json
from dataclasses import dataclass, field
from enum import StrEnum
from functools import cached_property
from pathlib import Path
from typing import Any


class ConnectorType(StrEnum):
    """Known OpenCTI connector types."""

    EXTERNAL_IMPORT = "EXTERNAL_IMPORT"
    INTERNAL_ENRICHMENT = "INTERNAL_ENRICHMENT"
    INTERNAL_EXPORT_FILE = "INTERNAL_EXPORT_FILE"
    INTERNAL_IMPORT_FILE = "INTERNAL_IMPORT_FILE"
    STREAM = "STREAM"

    @property
    def label(self) -> str:
        """Human-readable label derived from the value.

        Examples: EXTERNAL_IMPORT → 'External Import', STREAM → 'Stream'.
        """
        return self.value.replace("_", " ").title()


class Severity(StrEnum):
    """Severity levels for check results."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    def symbol(self) -> str:
        """Get a short symbol for the severity level."""
        return {"error": "E", "warning": "W", "info": "I"}[self.value]

    def rank(self) -> int:
        """Numeric rank for ordering (INFO=0, WARNING=1, ERROR=2)."""
        return {"info": 0, "warning": 1, "error": 2}[self.value]


# Shared severity → display mappings. Keyed by Severity enum for direct lookup.
SEVERITY_EMOJI: dict["Severity", str] = {
    Severity.ERROR: "🔴",
    Severity.WARNING: "🟡",
    Severity.INFO: "🔵",
}
SEVERITY_COLOR: dict["Severity", str] = {
    Severity.ERROR: "red",
    Severity.WARNING: "yellow",
    Severity.INFO: "cyan",
}


@dataclass
class CheckFinding:
    """A single finding produced by a check function.

    Contains only the check-specific data.  The runner enriches each
    finding with the ``code``, ``name`` and ``severity`` from the
    :class:`CheckDescriptor` to produce a full :class:`CheckResult`.
    """

    message: str
    severity: Severity  # override descriptor default (rare)
    file_path: Path | None = None
    line: int | None = None
    suggestion: str | None = None


@dataclass
class CheckResult:
    """Result of a single check execution."""

    code: str
    name: str
    message: str
    severity: Severity
    file_path: Path | None = None
    line: int | None = None
    suggestion: str | None = None


def no_python_sources_finding(suggestion: str | None = None) -> "CheckFinding":
    """Standard finding for checks that require Python source files but find none."""
    return CheckFinding(
        message="No Python source files found in src/",
        severity=Severity.ERROR,
        suggestion=suggestion or "Connector must have Python source files under src/",
    )


_DIR_TO_CONNECTOR_TYPE: dict[str, ConnectorType] = {
    "external-import": ConnectorType.EXTERNAL_IMPORT,
    "internal-enrichment": ConnectorType.INTERNAL_ENRICHMENT,
    "internal-export-file": ConnectorType.INTERNAL_EXPORT_FILE,
    "internal-import-file": ConnectorType.INTERNAL_IMPORT_FILE,
    "stream": ConnectorType.STREAM,
}


@dataclass
class ConnectorContext:
    """Contextual data about a connector, loaded once and shared across checks."""

    path: Path
    connector_type: ConnectorType | None = None
    manifest: dict[str, Any] = field(default_factory=dict)
    config_schema: dict[str, Any] = field(default_factory=dict)
    has_tests: bool = False
    has_dockerfile: bool = False
    has_readme: bool = False
    has_metadata_dir: bool = False
    src_files: list[Path] = field(default_factory=list)
    all_files: list[Path] = field(default_factory=list)

    @cached_property
    def python_sources(self) -> dict[Path, str]:
        """All Python source files under src/, keyed by path relative to connector root.

        Computed once and cached for the lifetime of this context.
        Uses src_files populated at load time to avoid re-scanning the filesystem.
        """
        sources: dict[Path, str] = {}
        for rel_path in self.src_files:
            abs_path = self.path / rel_path
            try:
                sources[rel_path] = abs_path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                continue
        return sources

    @cached_property
    def python_trees(self) -> dict[Path, ast.Module]:
        """Parsed AST modules for all Python source files.

        Computed once and cached for the lifetime of this context.
        Files with syntax errors are silently skipped.
        """
        trees: dict[Path, ast.Module] = {}
        for file_path, content in self.python_sources.items():
            try:
                trees[file_path] = ast.parse(content, filename=str(file_path))
            except SyntaxError:
                continue
        return trees

    @classmethod
    def load(cls, connector_path: Path) -> "ConnectorContext":
        """Load connector context from its directory."""
        ctx = cls(path=connector_path.resolve())

        # Detect connector type from parent directory name
        ctx.connector_type = _DIR_TO_CONNECTOR_TYPE.get(ctx.path.parent.name)
        # Fallback only for template layout: templates/<connector-kind>
        if ctx.connector_type is None and ctx.path.parent.name == "templates":
            ctx.connector_type = _DIR_TO_CONNECTOR_TYPE.get(ctx.path.name)

        # Load manifest
        manifest_path = ctx.path / "__metadata__" / "connector_manifest.json"
        if manifest_path.exists():
            try:
                with manifest_path.open() as f:
                    ctx.manifest = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass  # malformed or unreadable — checks that need it will report missing fields

        # Fallback: use container_type from manifest
        if ctx.connector_type is None and ctx.manifest.get("container_type"):
            try:
                ctx.connector_type = ConnectorType(ctx.manifest["container_type"])
            except ValueError:
                pass  # unknown type string — leave as None

        if ctx.connector_type is None:
            raise ValueError(
                "Unable to determine connector type for "
                f"'{ctx.path}'. Expected a connector directory nested under one "
                "of: external-import, internal-enrichment, internal-export-file, "
                "internal-import-file, stream, or templates/<connector-kind>; "
                "or provide '__metadata__/connector_manifest.json' with "
                "'container_type'."
            )

        # Load config schema
        schema_path = ctx.path / "__metadata__" / "connector_config_schema.json"
        if schema_path.exists():
            try:
                with schema_path.open() as f:
                    ctx.config_schema = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass  # malformed or unreadable — leave as empty dict

        # Detect structural elements
        ctx.has_metadata_dir = (ctx.path / "__metadata__").is_dir()
        ctx.has_tests = (ctx.path / "tests").is_dir()
        ctx.has_dockerfile = (ctx.path / "Dockerfile").is_file()
        ctx.has_readme = (ctx.path / "README.md").is_file()

        # Collect file lists
        ctx.all_files = [
            p.relative_to(ctx.path) for p in ctx.path.rglob("*") if p.is_file()
        ]
        ctx.src_files = [
            p.relative_to(ctx.path)
            for p in (ctx.path / "src").rglob("*.py")
            if p.is_file()
        ]

        return ctx
